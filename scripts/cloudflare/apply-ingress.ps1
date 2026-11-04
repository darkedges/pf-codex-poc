param([switch]$Activate,[switch]$Rollback)
$ErrorActionPreference='Stop'
if($Activate -and $Rollback){throw 'Select activation or rollback, not both.'}
$workspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$privateRoot=Join-Path $workspace '.local/cloudflare-connector'
$config=Join-Path $privateRoot 'config.yaml'
$candidate=Join-Path $workspace '.local/cloudflare-plan/activation-candidate.yaml'
$backup=Join-Path $privateRoot 'deny-all.backup.yaml'
$journal=Join-Path $privateRoot 'ingress-activation.json'
$receiptPath=Join-Path $privateRoot 'receipt.json'
$denyHash='03bbb62ba4859a8851fee71931d3b05e56c8966b747fedc2eebf337954299c34'
$publicHash='53d0d409c0eedaa2ef0a3439275fe9cb89cb239a66738c22abe6e4807e129422'
$tunnelId='a979d27b-f2cd-45cf-aada-b44c850e3a0e'
if(!$Activate -and !$Rollback){[ordered]@{mode='preview-only';candidateSha256=$publicHash;rollbackSha256=$denyHash;clientsRemainDisabled=$true;tunnelId=$tunnelId} | ConvertTo-Json;return}
if([Environment]::MachineName -ne 'DARKEDGES'){throw 'Dedicated host required.'}
$receipt=Get-Content $receiptPath -Raw | ConvertFrom-Json
$exe=Join-Path $workspace '.local/tools/cloudflared-2026.10.5/cloudflared.exe'
if($receipt.tunnelId -ne $tunnelId -or $receipt.executablePath -ne $exe -or (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'db4e4c413612a0916f3e1679d3caaf376f94911952d163028fb726fb2e0516a9'){throw 'Unexpected connector identity or executable.'}
$expectedCurrent=if($Activate){$denyHash}else{$publicHash}
if((Get-FileHash $config -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedCurrent){throw 'Active configuration changed; reconcile before proceeding.'}
$target=if($Activate){$candidate}else{$backup}
$expectedTarget=if($Activate){$publicHash}else{$denyHash}
if((Get-FileHash $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedTarget){throw 'Target configuration differs from the reviewed hash.'}
$validation=& $exe tunnel --config $target ingress validate 2>&1
if($LASTEXITCODE -ne 0){throw 'Target ingress validation failed.'}
if($Activate){
 $clients=& node (Join-Path $workspace 'scripts/pf/check-copilot-clients.mjs') 2>&1
 if($LASTEXITCODE -ne 0){throw 'Disabled client state could not be verified.'}
 if(Test-Path $journal){throw 'Activation journal already exists; reconcile instead of repeating activation.'}
 if(Test-Path $backup){if((Get-FileHash $backup -Algorithm SHA256).Hash.ToLowerInvariant() -ne $denyHash){throw 'Existing rollback backup differs.'}}else{[IO.File]::WriteAllBytes($backup,[IO.File]::ReadAllBytes($config))}
 $event=[ordered]@{status='activation-intent';approvedBy='user-explicit-Yes-Approved';at=[DateTime]::UtcNow.ToString('o');candidateSha256=$publicHash;rollbackSha256=$denyHash;clientsEnabled=$false}
 $stream=[IO.File]::Open($journal,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$writer=[IO.StreamWriter]::new($stream);$writer.Write(($event | ConvertTo-Json));$writer.Flush()}finally{$stream.Dispose()}
}else{$event=Get-Content $journal -Raw | ConvertFrom-Json;$event.status='rollback-intent';$event | ConvertTo-Json | Set-Content $journal -Encoding utf8}
$process=Get-CimInstance Win32_Process -Filter "ProcessId = $($receipt.connectorPid)"
if(!$process -or $process.ExecutablePath -ne $exe -or !$process.CommandLine.Contains($config) -or !$process.CommandLine.Contains($tunnelId)){throw 'Recorded process ownership differs; no process stopped.'}
[IO.File]::WriteAllBytes($config,[IO.File]::ReadAllBytes($target))
Stop-Process -Id $process.ProcessId
Wait-Process -Id $process.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
if(Get-NetTCPConnection -LocalPort 19473 -State Listen -ErrorAction SilentlyContinue){throw 'Metrics port occupied; no other process stopped.'}
$childEnvironment=@{}
Get-ChildItem Env: | Where-Object Name -Like 'TUNNEL_*' | ForEach-Object {$childEnvironment[$_.Name]=$null}
$started=Start-Process -FilePath $exe -ArgumentList @('tunnel','--config',('"'+$config+'"'),'run',$tunnelId) -Environment $childEnvironment -WindowStyle Hidden -RedirectStandardOutput (Join-Path $privateRoot 'ingress.stdout.log') -RedirectStandardError (Join-Path $privateRoot 'ingress.stderr.log') -PassThru
$receipt.connectorPid=$started.Id;$receipt.connectorStartedAt=[DateTime]::UtcNow.ToString('o');$receipt.publicRoutesEnabled=[bool]$Activate;$receipt.status='connector-starting-reviewed-ingress'
$receipt | ConvertTo-Json -Depth 8 | Set-Content $receiptPath -Encoding utf8
$ready=$false
for($attempt=0;$attempt -lt 15;$attempt++){try{$health=Invoke-WebRequest http://127.0.0.1:19473/ready -TimeoutSec 2 -SkipHttpErrorCheck;if([int]$health.StatusCode -eq 200){$ready=$true;break}}catch{};Start-Sleep -Seconds 1}
$event.status=if($ready){if($Activate){'activated-ready'}else{'rolled-back-ready'}}else{'readiness-recovery-required'}
$event | ConvertTo-Json -Depth 8 | Set-Content $journal -Encoding utf8
$receipt.status=if($ready){if($Activate){'connector-ready-reviewed-ingress'}else{'connector-ready-deny-all'}}else{'connector-readiness-recovery-required'}
$receipt | ConvertTo-Json -Depth 8 | Set-Content $receiptPath -Encoding utf8
[ordered]@{ready=$ready;publicPfRoutesEnabled=[bool]$Activate;connectorPid=$started.Id;oauthClientSettingsChanged=$false;activeConfigSha256=(Get-FileHash $config -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json
if(!$ready){throw 'Connector readiness failed; use protected rollback evidence and reconcile.'}

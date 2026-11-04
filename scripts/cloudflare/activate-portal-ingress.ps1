param([switch]$Rollback)
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Set-Location -LiteralPath $taskRoot
$taskCheck=if($Rollback){'--rollback'}else{'--check'}
& node scripts/vault/portal-activation-check.mjs $taskCheck
if($LASTEXITCODE -ne 0){throw 'Exact portal activation approval required'}
$taskReview=Join-Path $taskRoot '.local/tool-vault/portal-activation-review'
$taskManifest=Get-Content -LiteralPath (Join-Path $taskReview 'manifest.json') -Raw|ConvertFrom-Json
$taskPrivate=Join-Path $taskRoot '.local/cloudflare-connector'
$taskReceipt=Get-Content -LiteralPath (Join-Path $taskPrivate 'receipt.json') -Raw|ConvertFrom-Json
$taskConfig=Join-Path $taskPrivate 'config.yaml'
$taskTarget=Join-Path $taskReview $(if($Rollback){'tunnel.before.yaml'}else{'tunnel.candidate.yaml'})
$taskExpectedCurrent=if($Rollback){$taskManifest.candidateTunnelSha256}else{$taskManifest.sourceTunnelSha256}
$taskExpectedTarget=if($Rollback){$taskManifest.sourceTunnelSha256}else{$taskManifest.candidateTunnelSha256}
if($taskReceipt.tunnelId -cne 'a979d27b-f2cd-45cf-aada-b44c850e3a0e' -or $taskReceipt.cloudflaredVersion -cne '2026.10.5' -or (Get-FileHash -LiteralPath $taskReceipt.executablePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'db4e4c413612a0916f3e1679d3caaf376f94911952d163028fb726fb2e0516a9'){throw 'Pinned tunnel/executable required'}
$taskCurrentHash=(Get-FileHash -LiteralPath $taskConfig -Algorithm SHA256).Hash.ToLowerInvariant()
if($taskCurrentHash -ceq $taskExpectedTarget){@{alreadyApplied=$true;rollback=[bool]$Rollback}|ConvertTo-Json -Compress;exit}
if($taskCurrentHash -cne $taskExpectedCurrent -or (Get-FileHash -LiteralPath $taskTarget -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskExpectedTarget){throw 'Tunnel config drift; nothing stopped'}
& $taskReceipt.executablePath tunnel --config $taskTarget ingress validate
if($LASTEXITCODE -ne 0){throw 'Candidate tunnel ingress invalid'}
if(!$Rollback){$taskReady=Get-Content -LiteralPath (Join-Path $taskRoot '.local/tool-vault/portal-service/status.json') -Raw|ConvertFrom-Json;if($taskReady.state -ne 'ready' -or $taskReady.mode -ne 'staged' -or ([DateTime]::UtcNow-[DateTime]$taskReady.at).TotalSeconds -gt 35){throw 'Staged portal must be ready'}}
function Restart-OwnedPortalConnector([byte[]]$taskBytes){
 $taskProcess=Get-CimInstance Win32_Process -Filter "ProcessId = $($taskReceipt.connectorPid)"
 if(!$taskProcess -or $taskProcess.ExecutablePath -cne $taskReceipt.executablePath -or !$taskProcess.CommandLine.Contains($taskConfig) -or !$taskProcess.CommandLine.Contains($taskReceipt.tunnelId)){throw 'Connector ownership differs; no foreign process stopped'}
 [IO.File]::WriteAllBytes($taskConfig,$taskBytes)
 Stop-Process -Id $taskProcess.ProcessId
 Wait-Process -Id $taskProcess.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
 if(Get-NetTCPConnection -LocalPort 19473 -State Listen -ErrorAction SilentlyContinue){throw 'Metrics port occupied; no other process stopped'}
 $taskEnv=@{};Get-ChildItem Env:|Where-Object Name -Like 'TUNNEL_*'|ForEach-Object {$taskEnv[$_.Name]=$null}
 $taskChild=Start-Process -FilePath $taskReceipt.executablePath -ArgumentList @('tunnel','--config',('"'+$taskConfig+'"'),'run',$taskReceipt.tunnelId) -Environment $taskEnv -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskPrivate 'portal-ingress.stdout.log') -RedirectStandardError (Join-Path $taskPrivate 'portal-ingress.stderr.log') -PassThru
 $taskReceipt.connectorPid=$taskChild.Id;$taskReceipt.connectorStartedAt=[DateTime]::UtcNow.ToString('o');$taskReceipt|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $taskPrivate 'receipt.json') -Encoding utf8
 for($taskAttempt=0;$taskAttempt -lt 20;$taskAttempt++){try{if((Invoke-WebRequest http://127.0.0.1:19473/ready -TimeoutSec 2 -SkipHttpErrorCheck).StatusCode -eq 200){return $true}}catch{};Start-Sleep -Seconds 1}
 return $false
}
$taskBefore=[IO.File]::ReadAllBytes($taskConfig)
if(!(Restart-OwnedPortalConnector ([IO.File]::ReadAllBytes($taskTarget)))){if(!$Rollback){$taskRestored=Restart-OwnedPortalConnector $taskBefore;@{candidateHealthy=$false;sourceRestored=$taskRestored}|ConvertTo-Json -Compress};throw 'Tunnel activation not confirmed'}
$taskResult=@{verifiedAt=[DateTime]::UtcNow.ToString('o');portalIngressApplied=(!$Rollback);existingPfRelayRoutesPreserved=$true;activeConfigSha256=(Get-FileHash -LiteralPath $taskConfig -Algorithm SHA256).Hash.ToLowerInvariant();microsoftRequests=0}
$taskResult|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $taskReview 'ingress-applied.json') -Encoding utf8
$taskResult|ConvertTo-Json -Compress

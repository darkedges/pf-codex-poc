param([switch]$Rollback)
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$taskReview=Join-Path $taskRoot '.local/copilot/relay-microsoft-review'
$taskPrivate=Join-Path $taskRoot '.local/cloudflare-connector'
$taskManifest=Get-Content -LiteralPath (Join-Path $taskReview 'manifest.json') -Raw|ConvertFrom-Json
$taskApproval=Get-Content -LiteralPath (Join-Path $taskReview 'approval.json') -Raw|ConvertFrom-Json
$taskReceipt=Get-Content -LiteralPath (Join-Path $taskPrivate 'receipt.json') -Raw|ConvertFrom-Json
$taskExe=$taskReceipt.executablePath
$taskConfig=Join-Path $taskPrivate 'config.yaml'
$taskBackup=Join-Path $taskReview 'before-relay.yaml'
$taskCandidate=Join-Path $taskReview 'tunnel.review.yaml'
if($taskApproval.approved -ne $true -or $taskApproval.candidateTunnelSha256 -cne $taskManifest.candidateTunnelSha256 -or $taskReceipt.tunnelId -cne 'a979d27b-f2cd-45cf-aada-b44c850e3a0e' -or $taskReceipt.cloudflaredVersion -cne '2026.10.5' -or (Get-FileHash -LiteralPath $taskExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskReceipt.executableSha256){throw 'Approved tunnel identity required'}
$taskCurrentHash=(Get-FileHash -LiteralPath $taskConfig -Algorithm SHA256).Hash.ToLowerInvariant()
$taskExpectedCurrent=if($Rollback){$taskManifest.candidateTunnelSha256}else{$taskManifest.sourceTunnelSha256}
$taskExpectedTarget=if($Rollback){$taskManifest.sourceTunnelSha256}else{$taskManifest.candidateTunnelSha256}
$taskTarget=if($Rollback){$taskBackup}else{$taskCandidate}
if($taskCurrentHash -cne $taskExpectedCurrent -or (Get-FileHash -LiteralPath $taskTarget -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskExpectedTarget){throw 'Tunnel configuration drift; no process stopped'}
$taskValidation=& $taskExe tunnel --config $taskTarget ingress validate 2>&1
if($LASTEXITCODE -ne 0){throw 'Candidate ingress invalid'}
if(!$Rollback){$taskReady=Get-Content -LiteralPath (Join-Path $taskRoot '.local/tool-vault/relay-service/status.json') -Raw|ConvertFrom-Json;if($taskReady.state -ne 'ready' -or ([DateTime]::UtcNow-[DateTime]$taskReady.at).TotalSeconds -gt 35){throw 'Private relay must be ready'};if(Test-Path -LiteralPath $taskBackup){if((Get-FileHash -LiteralPath $taskBackup -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskManifest.sourceTunnelSha256){throw 'Backup differs'}}else{[IO.File]::WriteAllBytes($taskBackup,[IO.File]::ReadAllBytes($taskConfig))}}
$taskProcess=Get-CimInstance Win32_Process -Filter "ProcessId = $($taskReceipt.connectorPid)"
if(!$taskProcess -or $taskProcess.ExecutablePath -cne $taskExe -or !$taskProcess.CommandLine.Contains($taskConfig) -or !$taskProcess.CommandLine.Contains($taskReceipt.tunnelId)){throw 'Connector ownership differs; no process stopped'}
@{status='activation-intent';rollback=[bool]$Rollback;at=[DateTime]::UtcNow.ToString('o');targetSha256=$taskExpectedTarget}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $taskReview 'ingress-activation.json') -Encoding utf8
[IO.File]::WriteAllBytes($taskConfig,[IO.File]::ReadAllBytes($taskTarget))
Stop-Process -Id $taskProcess.ProcessId
Wait-Process -Id $taskProcess.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
if(Get-NetTCPConnection -LocalPort 19473 -State Listen -ErrorAction SilentlyContinue){throw 'Metrics port occupied; no other process stopped'}
$taskEnv=@{};Get-ChildItem Env:|Where-Object Name -Like 'TUNNEL_*'|ForEach-Object {$taskEnv[$_.Name]=$null}
$taskChild=Start-Process -FilePath $taskExe -ArgumentList @('tunnel','--config',('"'+$taskConfig+'"'),'run',$taskReceipt.tunnelId) -Environment $taskEnv -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskPrivate 'relay-ingress.stdout.log') -RedirectStandardError (Join-Path $taskPrivate 'relay-ingress.stderr.log') -PassThru
$taskReceipt.connectorPid=$taskChild.Id;$taskReceipt.connectorStartedAt=[DateTime]::UtcNow.ToString('o');$taskReceipt|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $taskPrivate 'receipt.json') -Encoding utf8
$taskHealthy=$false
for($taskAttempt=0;$taskAttempt -lt 20;$taskAttempt++){try{$taskResponse=Invoke-WebRequest http://127.0.0.1:19473/ready -TimeoutSec 2 -SkipHttpErrorCheck;if([int]$taskResponse.StatusCode -eq 200){$taskHealthy=$true;break}}catch{};Start-Sleep -Seconds 1}
$taskResult=@{ready=$taskHealthy;relayIngressApplied=(!$Rollback);existingPfRoutesPreserved=$true;connectorPid=$taskChild.Id;activeConfigSha256=(Get-FileHash -LiteralPath $taskConfig -Algorithm SHA256).Hash.ToLowerInvariant();at=[DateTime]::UtcNow.ToString('o')}
$taskResult|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $taskReview 'ingress-activation.json') -Encoding utf8
$taskResult|ConvertTo-Json -Compress
if(!$taskHealthy){throw 'Connector readiness requires recovery; exact backup is retained'}

param([switch]$Apply, [switch]$Rollback)
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Set-Location -LiteralPath $taskRoot
if (!$Apply -and !$Rollback) { @{action='preview';agentPort=9468;additionalPfEndpoint='/as/par.oauth2';dnsChanges=0;existingPfBRelayRoutesPreserved=$true} | ConvertTo-Json -Compress; exit }
& node --input-type=module -e 'import {assertMobileActivation} from "./scripts/vault/mobile-activation-guard.mjs"; assertMobileActivation();'
if ($LASTEXITCODE -ne 0) { throw 'Mobile activation approval required' }
$taskReview=Join-Path $taskRoot '.local/mobile/activation-review'
$taskPrepared=Get-Content -LiteralPath (Join-Path $taskReview 'preparation.json') -Raw | ConvertFrom-Json
$taskPrivate=Join-Path $taskRoot '.local/cloudflare-connector'
$taskReceiptPath=Join-Path $taskPrivate 'receipt.json'
$taskReceipt=Get-Content -LiteralPath $taskReceiptPath -Raw | ConvertFrom-Json
$taskConfig=Join-Path $taskPrivate 'config.yaml'
$taskBefore=Join-Path $taskReview 'tunnel.before.yaml'
$taskCandidate=Join-Path $taskReview 'tunnel.candidate.yaml'
$taskTarget=if($Rollback){$taskBefore}else{$taskCandidate}
$taskExpectedCurrent=if($Rollback){$taskPrepared.candidateTunnelSha256}else{$taskPrepared.sourceTunnelSha256}
$taskExpectedTarget=if($Rollback){$taskPrepared.sourceTunnelSha256}else{$taskPrepared.candidateTunnelSha256}
if ($taskReceipt.tunnelId -cne 'a979d27b-f2cd-45cf-aada-b44c850e3a0e' -or $taskReceipt.cloudflaredVersion -cne '2026.10.5' -or (Get-FileHash -LiteralPath $taskReceipt.executablePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'db4e4c413612a0916f3e1679d3caaf376f94911952d163028fb726fb2e0516a9') { throw 'Pinned owned tunnel/executable required' }
$taskCurrentHash=(Get-FileHash -LiteralPath $taskConfig -Algorithm SHA256).Hash.ToLowerInvariant()
if ($taskCurrentHash -ceq $taskExpectedTarget) { @{alreadyApplied=$true;rollback=[bool]$Rollback} | ConvertTo-Json -Compress; exit }
if ($taskCurrentHash -cne $taskExpectedCurrent -or (Get-FileHash -LiteralPath $taskTarget -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskExpectedTarget) { throw 'Tunnel configuration drift; nothing stopped' }
& $taskReceipt.executablePath tunnel --config $taskTarget ingress validate
if ($LASTEXITCODE -ne 0) { throw 'Mobile candidate ingress invalid' }
if (!$Rollback) {
    $taskStatus=Get-Content -LiteralPath (Join-Path $taskRoot '.local/tool-vault/mobile/service-status.json') -Raw | ConvertFrom-Json
    if ($taskStatus.state -cne 'ready' -or ([DateTime]::UtcNow-[DateTime]$taskStatus.at).TotalSeconds -gt 30) { throw 'Private mobile service must be ready before exposing its routes' }
}
function Restart-MobileConnector([byte[]]$taskBytes) {
    $taskOwned=Get-CimInstance Win32_Process -Filter "ProcessId = $($taskReceipt.connectorPid)"
    if (!$taskOwned -or $taskOwned.ExecutablePath -cne $taskReceipt.executablePath -or !$taskOwned.CommandLine.Contains($taskConfig) -or !$taskOwned.CommandLine.Contains($taskReceipt.tunnelId)) { throw 'Connector ownership changed; no foreign process stopped' }
    [IO.File]::WriteAllBytes($taskConfig,$taskBytes)
    Stop-Process -Id $taskOwned.ProcessId
    Wait-Process -Id $taskOwned.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
    if (Get-NetTCPConnection -LocalPort 19473 -State Listen -ErrorAction SilentlyContinue) { throw 'Metrics listener is occupied; nothing else stopped' }
    $taskEnvironment=@{}; Get-ChildItem Env: | Where-Object Name -Like 'TUNNEL_*' | ForEach-Object { $taskEnvironment[$_.Name]=$null }
    $taskChild=Start-Process -FilePath $taskReceipt.executablePath -ArgumentList @('tunnel','--loglevel','fatal','--config',('"'+$taskConfig+'"'),'run',$taskReceipt.tunnelId) -Environment $taskEnvironment -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskPrivate 'mobile-ingress.stdout.log') -RedirectStandardError (Join-Path $taskPrivate 'mobile-ingress.stderr.log') -PassThru
    $taskReceipt.connectorPid=$taskChild.Id;$taskReceipt.connectorStartedAt=[DateTime]::UtcNow.ToString('o');$taskReceipt|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $taskReceiptPath -Encoding utf8
    for($taskAttempt=0;$taskAttempt -lt 20;$taskAttempt++){try{if((Invoke-WebRequest http://127.0.0.1:19473/ready -TimeoutSec 1 -SkipHttpErrorCheck).StatusCode -eq 200){return $true}}catch{};Start-Sleep -Seconds 1}
    return $false
}
$taskOriginal=[IO.File]::ReadAllBytes($taskConfig)
if (!(Restart-MobileConnector ([IO.File]::ReadAllBytes($taskTarget)))) {
    if (!$Rollback) { $taskRestored=Restart-MobileConnector $taskOriginal; @{candidateHealthy=$false;sourceRestored=$taskRestored}|ConvertTo-Json -Compress }
    throw 'Mobile ingress readiness not confirmed'
}
@{applied=(!$Rollback);rollback=[bool]$Rollback;activeConfigSha256=(Get-FileHash -LiteralPath $taskConfig -Algorithm SHA256).Hash.ToLowerInvariant();dnsChanges=0;microsoftRequests=0}|ConvertTo-Json -Compress

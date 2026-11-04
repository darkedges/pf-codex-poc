param([switch]$Start, [switch]$Supervise)
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Set-Location -LiteralPath $taskRoot
if (!$Start) { @{ action='preview'; host='127.0.0.1'; port=9468; operatorCredential=$false } | ConvertTo-Json -Compress; exit }
$taskReview = Join-Path $taskRoot '.local/mobile/activation-review'
$taskManifest = Get-Content -LiteralPath (Join-Path $taskReview 'manifest.json') -Raw | ConvertFrom-Json
$taskApproval = Get-Content -LiteralPath (Join-Path $taskReview 'approval.json') -Raw | ConvertFrom-Json
if (!$taskApproval.approved -or $taskApproval.purpose -cne 'mobile-persistent-activation' -or (Get-FileHash -LiteralPath (Join-Path $taskReview 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskApproval.manifestSha256) { throw 'Exact mobile activation approval required' }
$taskNode = $taskManifest.node.path
if ((Get-FileHash -LiteralPath $taskNode -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskManifest.node.sha256) { throw 'Node executable differs' }
& $taskNode --input-type=module -e 'import {assertMobileActivation} from "./scripts/vault/mobile-activation-guard.mjs"; assertMobileActivation();'
if ($LASTEXITCODE -ne 0) { throw 'Mobile activation verification failed' }
$taskDirectory = Join-Path $taskRoot '.local/tool-vault/mobile'
$taskEntry = Join-Path $taskRoot 'scripts/vault/mobile-service.ts'
$taskConnection = Get-NetTCPConnection -LocalPort 9468 -State Listen -ErrorAction SilentlyContinue
$taskChild = $null
if ($taskConnection) {
    $taskStatus = Get-Content -LiteralPath (Join-Path $taskDirectory 'service-status.json') -Raw | ConvertFrom-Json
    $taskOwner = Get-CimInstance Win32_Process -Filter "ProcessId = $($taskStatus.pid)"
    if (@($taskConnection).Count -ne 1 -or $taskConnection.LocalAddress -cne '127.0.0.1' -or $taskConnection.OwningProcess -ne $taskStatus.pid -or $taskStatus.state -cne 'ready' -or ([DateTime]::UtcNow - [DateTime]$taskStatus.at).TotalSeconds -gt 30 -or !$taskOwner -or $taskOwner.ExecutablePath -cne $taskNode -or !$taskOwner.CommandLine.Contains($taskEntry)) { throw 'Existing listener is not the verified mobile service; nothing stopped' }
    $taskProcessId = $taskStatus.pid
} else {
    $taskStarted = [DateTime]::UtcNow
    $taskChild = Start-Process -FilePath $taskNode -ArgumentList @('--experimental-strip-types', ('"' + $taskEntry + '"'), '--serve') -WorkingDirectory $taskRoot -WindowStyle Hidden -PassThru
    $taskProcessId = $taskChild.Id
    $taskReady = $false
    for ($taskAttempt=0; $taskAttempt -lt 30; $taskAttempt++) {
        if ($taskChild.HasExited) { throw 'Mobile service exited during startup' }
        $taskFile = Join-Path $taskDirectory 'service-status.json'
        if (Test-Path -LiteralPath $taskFile) {
            try { $taskStatus=Get-Content -LiteralPath $taskFile -Raw | ConvertFrom-Json; if ($taskStatus.pid -eq $taskProcessId -and $taskStatus.state -ceq 'ready' -and [DateTime]$taskStatus.at -ge $taskStarted) { $taskReady=$true; break } } catch { }
        }
        Start-Sleep -Seconds 1
    }
    if (!$taskReady) { throw 'Mobile startup readiness was not confirmed; inspect the private status' }
}
@{ state='ready'; pid=$taskProcessId; host='127.0.0.1'; port=9468; operatorCredential=$false } | ConvertTo-Json -Compress
if ($Supervise) {
    Wait-Process -Id $taskProcessId -ErrorAction SilentlyContinue
    $taskFinal = Get-Content -LiteralPath (Join-Path $taskDirectory 'service-status.json') -Raw | ConvertFrom-Json
    if ($taskFinal.state -cne 'stopped') { exit 1 }
}

param([switch]$Install)
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$taskName='FederatedCopilotMobile'
if (!$Install) { @{action='preview';taskName=$taskName;logonType='Interactive';runLevel='Limited';storedPassword=$false;restartCount=3;operatorCredential=$false} | ConvertTo-Json -Compress; exit }
Set-Location -LiteralPath $taskRoot
& node --input-type=module -e 'import {assertMobileActivation} from "./scripts/vault/mobile-activation-guard.mjs"; assertMobileActivation();'
if ($LASTEXITCODE -ne 0) { throw 'Mobile activation approval required' }
$taskDirectory=Join-Path $taskRoot '.local/tool-vault/mobile'
if (!(Test-Path -LiteralPath (Join-Path $taskDirectory 'acceptance.json'))) { throw 'Owner phone/chat verification must be recorded before installing startup' }
$taskManifest=Get-Content -LiteralPath (Join-Path $taskRoot '.local/mobile/activation-review/manifest.json') -Raw | ConvertFrom-Json
$taskShell=$taskManifest.powershell.path
if ((Get-FileHash -LiteralPath $taskShell -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskManifest.powershell.sha256) { throw 'PowerShell executable differs' }
$taskIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($taskIdentity.User.Value -cne $taskManifest.ownerSid) { throw 'Startup must use the approved Windows account' }
$taskArguments='-NoProfile -WindowStyle Hidden -File "'+(Join-Path $taskRoot 'scripts/vault/start-mobile-service.ps1')+'" -Start -Supervise'
$taskDescription='Owned Federated Copilot Android startup: '+$taskRoot
$taskExisting=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($taskExisting) {
    if ($taskExisting.Description -cne $taskDescription -or @($taskExisting.Actions).Count -ne 1 -or $taskExisting.Actions[0].Execute -cne $taskShell -or $taskExisting.Actions[0].Arguments -cne $taskArguments -or $taskExisting.Principal.RunLevel -ne 'Limited' -or $taskExisting.Principal.LogonType -ne 'Interactive') { throw 'A different startup task exists; nothing overwritten' }
} else {
    $taskAction=New-ScheduledTaskAction -Execute $taskShell -Argument $taskArguments -WorkingDirectory $taskRoot
    $taskTrigger=New-ScheduledTaskTrigger -AtLogOn -User $taskIdentity.Name
    $taskPrincipal=New-ScheduledTaskPrincipal -UserId $taskIdentity.Name -LogonType Interactive -RunLevel Limited
    $taskSettings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings | Out-Null
}
Start-ScheduledTask -TaskName $taskName
@{installed=$true;taskName=$taskName;account=$taskIdentity.Name;runLevel='Limited';storedPassword=$false;operatorCredential=$false} | ConvertTo-Json -Compress

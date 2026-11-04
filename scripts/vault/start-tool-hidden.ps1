$ErrorActionPreference='Stop'
$workspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Set-Location -LiteralPath $workspace
if(Test-Path -LiteralPath '.local/tool-vault/service-controller.lock'){throw 'Existing controller must be stopped before restart'}
$taskStamp=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N')
$taskOut=Join-Path $workspace ".local/tool-vault/service/controller-$taskStamp.out"
$taskErr=Join-Path $workspace ".local/tool-vault/service/controller-$taskStamp.err"
$taskProcess=Start-Process -FilePath (Get-Command node).Source -ArgumentList @('--experimental-strip-types','scripts/vault/service.mjs','--serve') -WorkingDirectory $workspace -WindowStyle Hidden -RedirectStandardOutput $taskOut -RedirectStandardError $taskErr -PassThru
@{pid=$taskProcess.Id;automaticRestart=$false}|ConvertTo-Json -Compress

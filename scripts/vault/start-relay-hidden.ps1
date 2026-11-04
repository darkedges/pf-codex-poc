$ErrorActionPreference='Stop'
$taskWorkspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Set-Location -LiteralPath $taskWorkspace
if(Test-Path -LiteralPath '.local/tool-vault/relay-controller.lock'){throw 'Managed relay must be stopped or recovered before startup'}
$taskStamp=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N')
$taskOut=Join-Path $taskWorkspace ".local/tool-vault/relay-service/controller-$taskStamp.out"
$taskErr=Join-Path $taskWorkspace ".local/tool-vault/relay-service/controller-$taskStamp.err"
$taskProcess=Start-Process -FilePath (Get-Command node).Source -ArgumentList @('--experimental-strip-types','scripts/vault/managed-relay-service.mjs','--serve') -WorkingDirectory $taskWorkspace -WindowStyle Hidden -RedirectStandardOutput $taskOut -RedirectStandardError $taskErr -PassThru
@{pid=$taskProcess.Id;automaticRestart=$false;publicIngress=$false}|ConvertTo-Json -Compress

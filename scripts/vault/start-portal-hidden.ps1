param([switch]$Live)
$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Set-Location -LiteralPath $taskRoot
if(Test-Path -LiteralPath '.local/tool-vault/portal-controller.lock'){throw 'Portal must be stopped or recovered before startup'}
$taskDirectory=Join-Path $taskRoot '.local/tool-vault/portal-service'
New-Item -ItemType Directory -Path $taskDirectory -Force|Out-Null
$taskStamp=[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N')
$env:NODE_EXTRA_CA_CERTS=Join-Path $taskRoot '.local/pingfederate/ca.pem'
$taskAction=if($Live){'--serve-live'}else{'--serve'}
$taskProcess=Start-Process -FilePath (Get-Command node).Source -ArgumentList @('--experimental-strip-types','scripts/vault/portal-service.mjs',$taskAction) -WorkingDirectory $taskRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskDirectory "controller-$taskStamp.out") -RedirectStandardError (Join-Path $taskDirectory "controller-$taskStamp.err") -PassThru
@{pid=$taskProcess.Id;mode=$(if($Live){'live'}else{'staged'});automaticRestart=$false;host='127.0.0.1';port=9466}|ConvertTo-Json -Compress

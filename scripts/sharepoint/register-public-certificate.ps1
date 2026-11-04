param([Parameter(Mandatory)][string]$RequestFile)
$ErrorActionPreference='Stop'
try{
    $taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $taskExpected=Join-Path $taskRoot '.local/sharepoint/requests/register-public-certificate.json'
    if([IO.Path]::GetFullPath($RequestFile) -ne $taskExpected){throw 'Unexpected request file'}
    $taskInput=Get-Content -LiteralPath $RequestFile -Raw|ConvertFrom-Json
    if($taskInput.url -ne 'https://graph.microsoft.com/v1.0/applications/3909f112-ddaf-4a34-b922-586179d5b5d9' -or @($taskInput.body.PSObject.Properties.Name).Count -ne 1 -or $taskInput.body.PSObject.Properties.Name -ne 'keyCredentials' -or @($taskInput.body.keyCredentials).Count -ne 1){throw 'Unexpected registration scope'}
    $taskAz=(Get-Command az.cmd).Source
    $taskPython=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetDirectoryName($taskAz)) '../python.exe'))
    $taskBody=$RequestFile+'.body'
    $taskInput.body|ConvertTo-Json -Depth 12 -Compress|Set-Content -LiteralPath $taskBody -Encoding utf8NoBOM
    try{& $taskPython -IBm azure.cli rest --method PATCH --url $taskInput.url --headers 'Content-Type=application/json' --body ('@'+$taskBody) --output none --only-show-errors 2>$null;if($LASTEXITCODE -ne 0){throw 'Registration unconfirmed'}}finally{Remove-Item -LiteralPath $taskBody -Force}
}catch{[Console]::Error.WriteLine('Exact public certificate registration failed. No automatic retry.');exit 1}

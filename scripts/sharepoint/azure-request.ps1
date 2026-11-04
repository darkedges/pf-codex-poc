param([Parameter(Mandatory=$true)][string]$RequestFile)
$ErrorActionPreference='Stop'
try {
    $taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $taskDirectory=[IO.Path]::GetFullPath((Join-Path $taskRoot '.local/sharepoint/requests'))
    $taskPath=[IO.Path]::GetFullPath($RequestFile)
    if([IO.Path]::GetDirectoryName($taskPath) -ne $taskDirectory){throw 'Invalid request path'}
    $taskRequest=Get-Content -LiteralPath $taskPath -Raw | ConvertFrom-Json
    # Invoke the installed CLI's Python entry point directly. The az.cmd launcher
    # reparses Graph query '&' characters through cmd.exe on Windows.
    $taskAzLauncher=(Get-Command az.cmd -ErrorAction Stop).Source
    $taskAzPython=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetDirectoryName($taskAzLauncher)) '../python.exe'))
    if(-not (Test-Path -LiteralPath $taskAzPython -PathType Leaf)){throw 'Installed Azure CLI runtime missing'}
    if($taskRequest.kind -eq 'identity'){
        $taskResult=& $taskAzPython -IBm azure.cli account show --query '{tenantId:tenantId,user:user.name}' --output json --only-show-errors 2>$null
    }else{
        $taskUri=[Uri]$taskRequest.url
        if($taskRequest.kind -ne 'graph' -or $taskRequest.method -notin @('GET','POST') -or $taskUri.Scheme -ne 'https' -or $taskUri.Host -ne 'graph.microsoft.com' -or $taskUri.Port -ne 443 -or $taskUri.UserInfo -or $taskUri.Fragment -or -not $taskUri.AbsolutePath.StartsWith('/v1.0/')){throw 'Invalid Graph endpoint'}
        $taskArguments=@('rest','--method',[string]$taskRequest.method,'--url',[string]$taskRequest.url,'--output','json','--only-show-errors')
        $taskBodyPath=$taskPath+'.body'
        if($null -ne $taskRequest.body){
            $taskRequest.body | ConvertTo-Json -Depth 20 -Compress | Set-Content -LiteralPath $taskBodyPath -Encoding utf8NoBOM
            $taskArguments+=@('--headers','Content-Type=application/json','--body',('@'+$taskBodyPath))
        }
        try {$taskResult=& $taskAzPython -IBm azure.cli @taskArguments 2>$null}finally{if(Test-Path -LiteralPath $taskBodyPath){Remove-Item -LiteralPath $taskBodyPath -Force}}
    }
    if($LASTEXITCODE -ne 0){throw 'Request failed'}
    $taskResult
}catch{[Console]::Error.WriteLine('Approved Azure metadata/setup request failed. No automatic retry.');exit 1}

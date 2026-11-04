$ErrorActionPreference='Stop'
$taskRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$taskDirectory=Join-Path $taskRoot '.local/sharepoint'
$taskStatePath=Join-Path $taskDirectory 'admin-site-grant-result.json'
$taskLockPath=Join-Path $taskDirectory 'admin-site-grant.lock'
$taskLock=$null
$taskPhase='approval'
try {
    $taskApproval=Get-Content (Join-Path $taskDirectory 'admin-owner-approval.json') -Raw | ConvertFrom-Json
    $taskReviewHash=(Get-FileHash -LiteralPath (Join-Path $taskRoot 'docs/sharepoint-admin-grant-review.md') -Algorithm SHA256).Hash.ToLowerInvariant()
    if($taskApproval.approved -ne $true -or $taskApproval.answer -ne 'Approve administrator setup authorization' -or $taskApproval.reviewSha256 -ne $taskReviewHash){throw 'Missing exact approval'}
    $taskOriginalReceipt=Get-Content (Join-Path $taskDirectory 'e1e824b98ddf87eb1588cafbb2ff6ba9117a6fa0a0eedb0644c6c11b8113a2f3.receipt.json') -Raw | ConvertFrom-Json
    if($taskOriginalReceipt.appId -ne 'cddeda93-51e4-42ad-bba7-b85b38b51b72' -or $taskOriginalReceipt.status -ne 'site-read-intent'){throw 'Existing setup receipt mismatch'}
    $taskLock=[IO.File]::Open($taskLockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.36.1 -ErrorAction Stop
    Import-Module (Join-Path $PSScriptRoot 'admin-site-grant.psm1') -Force
    $taskPhase='administrator-sign-in'
    Connect-MgGraph -TenantId '4161be3f-bf2b-41d4-a02b-e6f82b529d53' -ClientId '14d82eec-204b-4c2f-b7e8-296a70dab67e' -Scopes 'Sites.FullControl.All' -ContextScope Process -UseDeviceCode -NoWelcome -ClientTimeout 30
    Set-MgRequestContext -MaxRetry 0 -ClientTimeout 30 | Out-Null
    if((Get-MgRequestContext).MaxRetry -ne 0){throw 'Retries must be disabled'}
    $taskPhase='site-grant-reconciliation'
    $taskResult=Invoke-ApprovedSiteGrant -Context {Get-MgContext} -ReadState {
        if(Test-Path -LiteralPath $taskStatePath){Get-Content -LiteralPath $taskStatePath -Raw | ConvertFrom-Json -AsHashtable}
    } -WriteState {
        param($value)
        $temp=$taskStatePath+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
        $value | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $temp -Encoding utf8NoBOM
        [IO.File]::Move($temp,$taskStatePath,$true)
    } -Request {
        param($method,$uri,$body)
        $parameters=@{Method=$method;Uri=$uri;OutputType='Hashtable';ErrorAction='Stop'}
        if($null -ne $body){$parameters.Body=($body | ConvertTo-Json -Depth 10 -Compress);$parameters.ContentType='application/json'}
        Invoke-MgGraphRequest @parameters
    }
    $taskResult | ConvertTo-Json -Depth 10
}catch{
    @{verified=$false;phase=$taskPhase;automaticRetry=$false;graphDocumentRead=$false} | ConvertTo-Json -Compress | Write-Output
    exit 1
}finally{
    if(Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue){Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null}
    if($null -ne $taskLock){$taskLock.Dispose();Remove-Item -LiteralPath $taskLockPath -Force}
}

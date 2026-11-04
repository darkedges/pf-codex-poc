$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../scripts/sharepoint/admin-site-grant.psm1') -Force
$script:posts=0
$script:state=$null
$script:permission=@{id='p1';roles=@('read');grantedToIdentitiesV2=@(@{application=@{id='cddeda93-51e4-42ad-bba7-b85b38b51b72'}})}
function Assert-True($Value){if(-not $Value){throw 'Assertion failed'}}
function Expect-Failure([scriptblock]$Action){$taskFailed=$false;try{& $Action | Out-Null}catch{$taskFailed=$true};Assert-True $taskFailed}
$context={@{TenantId='4161be3f-bf2b-41d4-a02b-e6f82b529d53';Account='admin@nirvingukhotmail.onmicrosoft.com';ClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e';AuthType='Delegated';ContextScope='Process';Scopes=@('Sites.FullControl.All')}}
$read={ $script:state }
$write={param($Value) $script:state=$Value}
$request={param($Method,$Uri,$Body) if($Method -eq 'POST'){$script:posts++;return $script:permission};@{value=@($script:permission)}}
$result=Invoke-ApprovedSiteGrant -Context $context -ReadState $read -WriteState $write -Request $request
Assert-True ($result.status -eq 'verified-existing-read-grant' -and $script:posts -eq 0)
$script:state=$null
$requestMissing={param($Method,$Uri,$Body) if($Method -eq 'POST'){Assert-True ($script:state.status -eq 'grant-post-intent');Assert-True ($Body.roles.Count -eq 1 -and $Body.roles[0] -eq 'read');$script:posts++;return $script:permission};if($script:posts){return @{value=@($script:permission)}};@{value=@()}}
$result=Invoke-ApprovedSiteGrant -Context $context -ReadState $read -WriteState $write -Request $requestMissing
Assert-True ($result.status -eq 'verified-new-read-grant' -and $script:posts -eq 1)
# Existing intent may be reconciled by reads, never repeated as another mutation.
$script:state=@{status='grant-post-intent'};$script:posts=0
Expect-Failure {Invoke-ApprovedSiteGrant -Context $context -ReadState $read -WriteState $write -Request {param($m,$u,$b) if($m -eq 'POST'){throw 'Must not write'};@{value=@()}}}
$script:state=$null
foreach($bad in @(@{value=@();'@odata.nextLink'='https://other.test'},@{value=@(@{id='x';roles=@('write');grantedToIdentitiesV2=$script:permission.grantedToIdentitiesV2})},@{value=@($script:permission,$script:permission)})){
 $script:bad=$bad;Expect-Failure {Invoke-ApprovedSiteGrant -Context $context -ReadState $read -WriteState $write -Request {param($m,$u,$b) if($m -eq 'POST'){throw 'Must not write'};$script:bad}}
}
Expect-Failure {Invoke-ApprovedSiteGrant -Context {@{TenantId='wrong'}} -ReadState $read -WriteState $write -Request {throw 'Must not request'}}
$script:state=$null
Expect-Failure {Invoke-ApprovedSiteGrant -Context $context -ReadState $read -WriteState $write -Request {param($m,$u,$b) if($m -eq 'POST'){throw 'Lost response'};@{value=@()}}}
Assert-True ($script:state.status -eq 'grant-post-intent')
'SharePoint admin-grant checks passed: existing/missing grant, intent, uncertainty, duplicate/write/pagination and wrong identity.'

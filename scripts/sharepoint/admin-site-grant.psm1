Set-StrictMode -Version Latest
function Invoke-ApprovedSiteGrant {
    param([Parameter(Mandatory)][scriptblock]$Context,[Parameter(Mandatory)][scriptblock]$ReadState,[Parameter(Mandatory)][scriptblock]$WriteState,[Parameter(Mandatory)][scriptblock]$Request)
    $ErrorActionPreference='Stop'
    $taskApp='cddeda93-51e4-42ad-bba7-b85b38b51b72'
    $taskSite='nirvingukhotmail.sharepoint.com,b353bf73-309c-474b-85a2-f3635a7cceff,f8d6bb5e-6c9d-41c8-bd53-0cd08796061e'
    $taskUri='https://graph.microsoft.com/v1.0/sites/'+$taskSite+'/permissions'
    function Assert-Context {
        $c=& $Context
        if($c.TenantId -ne '4161be3f-bf2b-41d4-a02b-e6f82b529d53' -or $c.Account -ne 'admin@nirvingukhotmail.onmicrosoft.com' -or $c.ClientId -ne '14d82eec-204b-4c2f-b7e8-296a70dab67e' -or $c.AuthType -ne 'Delegated' -or $c.ContextScope -ne 'Process' -or @($c.Scopes) -notcontains 'Sites.FullControl.All'){throw 'Administrator context mismatch'}
    }
    function Get-MatchingPermissions {
        Assert-Context
        $v=& $Request 'GET' $taskUri $null
        if($v -isnot [System.Collections.IDictionary] -or -not $v.Contains('value') -or $v.Contains('@odata.nextLink') -or $v.value -isnot [System.Collections.IList] -or $v.value.Count -gt 100){throw 'Ambiguous site permission response'}
        foreach($p in $v.value){
            $identities=@();if($p.Contains('grantedToIdentitiesV2')){$identities+=@($p.grantedToIdentitiesV2)};if($p.Contains('grantedToIdentities')){$identities+=@($p.grantedToIdentities)}
            $matches=@($identities | Where-Object {$_.Contains('application') -and $_.application.id -eq $taskApp})
            if($matches.Count){
                if(-not $p.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$p.id) -or @($p.roles).Count -ne 1 -or $p.roles[0] -ne 'read'){throw 'Conflicting broker grant'}
                foreach($field in @('grantedToIdentitiesV2','grantedToIdentities')){if($p.Contains($field)){$items=@($p[$field]);if($items.Count -ne 1 -or -not $items[0].Contains('application') -or $items[0].application.id -ne $taskApp -or $items[0].Contains('user')){throw 'Conflicting identities'}}}
                $p
            }
        }
    }
    $taskPrior=& $ReadState
    $taskMatches=@(Get-MatchingPermissions)
    if($taskMatches.Count -gt 1){throw 'Duplicate broker grants'}
    if($taskMatches.Count -eq 1){
        $taskResult=@{status='verified-existing-read-grant';appId=$taskApp;siteId=$taskSite;permissionId=[string]$taskMatches[0].id;roles=@('read');verifiedAt=[DateTime]::UtcNow.ToString('o');newPosts=0}
        & $WriteState $taskResult | Out-Null
        return $taskResult
    }
    if($null -ne $taskPrior){throw 'Previous reconciliation requires independent review; no repeated POST'}
    Assert-Context
    & $WriteState @{status='grant-post-intent';appId=$taskApp;siteId=$taskSite;at=[DateTime]::UtcNow.ToString('o')} | Out-Null
    $taskBody=@{roles=@('read');grantedToIdentities=@(@{application=@{id=$taskApp;displayName='copilot-m365-resource-broker'}})}
    # Exactly one invocation; the host disables Graph SDK retries before calling.
    $taskCreated=& $Request 'POST' $taskUri $taskBody
    if($taskCreated -isnot [System.Collections.IDictionary] -or -not $taskCreated.Contains('id')){throw 'Unconfirmed POST'}
    $taskMatches=@(Get-MatchingPermissions)
    if($taskMatches.Count -ne 1 -or $taskMatches[0].id -ne $taskCreated.id){throw 'Grant readback mismatch'}
    $taskResult=@{status='verified-new-read-grant';appId=$taskApp;siteId=$taskSite;permissionId=[string]$taskMatches[0].id;roles=@('read');verifiedAt=[DateTime]::UtcNow.ToString('o');newPosts=1}
    & $WriteState $taskResult | Out-Null
    $taskResult
}
Export-ModuleMember -Function Invoke-ApprovedSiteGrant

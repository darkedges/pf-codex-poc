# Local Windows lab credential entry. Production should mount credentials from a secret manager.
param([ValidateSet('DirectLine','CloudflareDns')][string]$CredentialKind='DirectLine',[switch]$BindCurrentAgent)
$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localRoot = Join-Path $workspace '.local'
$directory = Join-Path $localRoot 'copilot'
$target = Join-Path $directory $(if($CredentialKind -eq 'CloudflareDns'){'cloudflare-dns-api-token.txt'}else{'direct-line-secret.txt'})
$bindingSettings=$null
if($BindCurrentAgent){
    if($CredentialKind -ne 'DirectLine'){throw 'Agent binding is only valid for Direct Line.'}
    $bindingSettings=Get-Content -LiteralPath (Join-Path $directory 'channel-settings.json') -Raw | ConvertFrom-Json
    foreach($field in @('tenantId','environmentId','copilotId')){
        if([string]$bindingSettings.$field -notmatch '^[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$'){throw 'Explicit channel target configuration required.'}
    }
    if([string]$bindingSettings.schemaName -notmatch '^[A-Za-z0-9_]{1,200}$'){throw 'Explicit channel schema required.'}
    Write-Host ('Bind a secret copied from this exact agent: '+$bindingSettings.schemaName+' / '+$bindingSettings.copilotId)
}
foreach ($candidate in @($localRoot, $directory, $target)) {
    if ((Test-Path -LiteralPath $candidate) -and ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Credential path must not contain a reparse point.'
    }
}
[IO.Directory]::CreateDirectory($directory) > $null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach ($sid in @($identity.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}
# Persist only the modified DACL. Set-Acl can request audit (SACL) access on an
# already protected directory, which requires SeSecurityPrivilege. Ownership and
# auditing must stay unchanged; neither is needed to restrict credential readers.
[IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($directory), $acl)
$verifiedAcl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($directory), [Security.AccessControl.AccessControlSections]::Access)
$verifiedRules = @($verifiedAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if (-not $verifiedAcl.AreAccessRulesProtected -or $verifiedRules.Count -ne 2) {
    throw 'Credential directory permissions could not be verified.'
}
foreach ($rule in $verifiedRules) {
    if ($rule.IdentityReference.Value -notin @($identity.User.Value, 'S-1-5-18') -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
        throw 'Unexpected credential directory permissions.'
    }
}
$prompt=if($CredentialKind -eq 'CloudflareDns'){'Paste the Cloudflare darkedges.com DNS API token (input hidden)'}else{'Paste the Direct Line channel secret (input hidden)'}
$value = Read-Host $prompt -AsSecureString
$pointer = [IntPtr]::Zero
$temporary = Join-Path $directory ('.secret-' + [guid]::NewGuid().ToString('N'))
try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($value)
    $secretText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrWhiteSpace($secretText) -or $secretText.Length -gt 16000 -or $secretText.Contains("`r") -or $secretText.Contains("`n")) {
        throw 'Secret must be a nonempty single line of at most 16000 characters.'
    }
    if($CredentialKind -eq 'CloudflareDns' -and $secretText.Trim() -notmatch '^[A-Za-z0-9._-]{20,1024}$'){throw 'Cloudflare API token must be a single token without spaces, headers or URLs.'}
    [IO.File]::WriteAllText($temporary, $secretText.Trim(), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporary, $target, $true)
    if($BindCurrentAgent){
        $binding=[ordered]@{version=1;tenantId=$bindingSettings.tenantId;environmentId=$bindingSettings.environmentId;copilotId=$bindingSettings.copilotId;schemaName=$bindingSettings.schemaName;credentialSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($secretText.Trim()))).ToLowerInvariant();savedAt=[DateTime]::UtcNow.ToString('o');source='operator-confirmed-agent-channel'}
        $bindingTemporary=Join-Path $directory ('.binding-'+[guid]::NewGuid().ToString('N'))
        try{[IO.File]::WriteAllText($bindingTemporary,($binding|ConvertTo-Json),[Text.UTF8Encoding]::new($false));[IO.File]::Move($bindingTemporary,(Join-Path $directory 'channel-credential-binding.json'),$true)}finally{if(Test-Path -LiteralPath $bindingTemporary){Remove-Item -LiteralPath $bindingTemporary -Force}}
        Write-Host 'Operator target binding saved; actual remote channel ownership still needs live verification.'
    }
    Write-Host "Credential saved to protected local file: $target"
    Write-Host 'No network request was made. Do not paste this secret into chat or commit it.'
} finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    $secretText = $null
    if ($value) { $value.Dispose() }
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
}

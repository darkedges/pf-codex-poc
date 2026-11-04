$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fixtureRoot = Join-Path (Join-Path $workspace '.local') ('credential-test-' + [guid]::NewGuid().ToString('N'))
$helperDirectory = Join-Path $fixtureRoot 'scripts/copilot'
$credentialDirectory = Join-Path $fixtureRoot '.local/copilot'
$helper = Join-Path $helperDirectory 'store-direct-line-secret.ps1'
$credentialFile = Join-Path $credentialDirectory 'direct-line-secret.txt'
$source = Join-Path $workspace 'scripts/copilot/store-direct-line-secret.ps1'
function Assert-That([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Read-Host { param([string]$Prompt, [switch]$AsSecureString) return ConvertTo-SecureString $global:copilotSecretFixtureInput -AsPlainText -Force }
function Verify-Access {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $accessSection = [Security.AccessControl.AccessControlSections]::Access
    $directoryAcl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($credentialDirectory),$accessSection)
    Assert-That $directoryAcl.AreAccessRulesProtected 'Directory inheritance must be disabled'
    foreach ($path in @($credentialDirectory,$credentialFile)) {
        $acl = Get-Acl -LiteralPath $path
        $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        Assert-That ($rules.Count -eq 2) 'Only two access rules are expected'
        foreach ($rule in $rules) {
            Assert-That ($rule.IdentityReference.Value -in @($sid,'S-1-5-18')) 'Unexpected credential reader'
            Assert-That ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) 'Unexpected access rule'
            Assert-That ($rule.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl) 'Expected current-user/SYSTEM access'
        }
    }
}
try {
    [IO.Directory]::CreateDirectory($helperDirectory) > $null
    [IO.Directory]::CreateDirectory($credentialDirectory) > $null
    Copy-Item -LiteralPath $source -Destination $helper
    $ownerBefore = (Get-Acl -LiteralPath $credentialDirectory).Owner
    $global:copilotSecretFixtureInput = 'TEST_ONLY_CHANNEL_VALUE_' + [guid]::NewGuid().ToString('N')
    $output = (& $helper 6>&1 | Out-String)
    Assert-That ($output -notlike "*$global:copilotSecretFixtureInput*") 'Secret was printed'
    Assert-That ([IO.File]::ReadAllText($credentialFile) -ceq $global:copilotSecretFixtureInput) 'Credential contents mismatch'
    Assert-That ((Get-Acl -LiteralPath $credentialDirectory).Owner -eq $ownerBefore) 'Helper must not change ownership'
    Verify-Access
    Write-Host 'PASS: save, DACL restriction, unchanged owner and no credential output'
    $global:copilotSecretFixtureInput = 'TEST_ONLY_REPLACEMENT_' + [guid]::NewGuid().ToString('N')
    $output = (& $helper 6>&1 | Out-String)
    Assert-That ($output -notlike "*$global:copilotSecretFixtureInput*") 'Replacement credential was printed'
    Assert-That ([IO.File]::ReadAllText($credentialFile) -ceq $global:copilotSecretFixtureInput) 'Replacement failed'
    Verify-Access
    Write-Host 'PASS: existing credential replacement preserves restricted access'
    $previous = $global:copilotSecretFixtureInput
    # Use an embedded newline: SecureString cannot be built from an empty string.
    $global:copilotSecretFixtureInput = "TEST_ONLY_INVALID`nINPUT"
    $rejected = $false
    try { & $helper > $null } catch { $rejected = $_.Exception.Message -like '*single line*' }
    Assert-That $rejected 'Multiline input must fail validation'
    Assert-That ([IO.File]::ReadAllText($credentialFile) -ceq $previous) 'Invalid input changed the existing credential'
    Assert-That (@(Get-ChildItem -LiteralPath $credentialDirectory -Filter '.secret-*' -Force).Count -eq 0) 'Temporary credential file left behind'
    Write-Host 'PASS: invalid input rejected without replacing the saved credential'
    $settingsFile=Join-Path $credentialDirectory 'channel-settings.json'
    $fixtureSettings=[ordered]@{tenantId='11111111-2222-4333-8444-555555555555';environmentId='22222222-2222-4333-8444-555555555555';copilotId='33333333-2222-4333-8444-555555555555';schemaName='test_agent'}
    [IO.File]::WriteAllText($settingsFile,($fixtureSettings|ConvertTo-Json))
    $global:copilotSecretFixtureInput='TEST_ONLY_BOUND_'+[guid]::NewGuid().ToString('N')
    $output=(& $helper -BindCurrentAgent 6>&1|Out-String)
    $bindingFile=Join-Path $credentialDirectory 'channel-credential-binding.json'
    $binding=Get-Content -LiteralPath $bindingFile -Raw|ConvertFrom-Json
    Assert-That ($output -notlike "*$global:copilotSecretFixtureInput*") 'Binding printed the secret'
    Assert-That ($binding.version -eq 1 -and $binding.copilotId -eq $fixtureSettings.copilotId -and $binding.schemaName -eq 'test_agent') 'Binding target differs'
    $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($global:copilotSecretFixtureInput))).ToLowerInvariant()
    Assert-That ($binding.credentialSha256 -ceq $digest) 'Binding does not match saved credential'
    Verify-Access
    $previous=$global:copilotSecretFixtureInput
    $oldBinding=[IO.File]::ReadAllText($bindingFile)
    $fixtureSettings.copilotId='not-a-guid';[IO.File]::WriteAllText($settingsFile,($fixtureSettings|ConvertTo-Json))
    $rejected=$false;try{& $helper -BindCurrentAgent > $null}catch{$rejected=$true}
    Assert-That $rejected 'Malformed agent target must be rejected'
    Assert-That ([IO.File]::ReadAllText($credentialFile) -ceq $previous) 'Bad target changed credential'
    Assert-That ([IO.File]::ReadAllText($bindingFile) -ceq $oldBinding) 'Bad target changed binding'
    Assert-That (@(Get-ChildItem -LiteralPath $credentialDirectory -Filter '.binding-*' -Force).Count -eq 0) 'Temporary binding file remains'
    $rejected=$false;try{& $helper -CredentialKind CloudflareDns -BindCurrentAgent > $null}catch{$rejected=$true}
    Assert-That $rejected 'Cloudflare credential must not bind to an agent'
    Write-Host 'PASS: exact-agent binding is protected, redacted and unchanged on invalid target/kind'
    $global:copilotSecretFixtureInput = 'TEST_ONLY_CLOUDFLARE_' + [guid]::NewGuid().ToString('N')
    $output = (& $helper -CredentialKind CloudflareDns 6>&1 | Out-String)
    $dnsFile = Join-Path $credentialDirectory 'cloudflare-dns-api-token.txt'
    Assert-That ($output -notlike "*$global:copilotSecretFixtureInput*") 'Cloudflare token was printed'
    Assert-That ([IO.File]::ReadAllText($dnsFile) -ceq $global:copilotSecretFixtureInput) 'Cloudflare token was not stored separately'
    Assert-That ([IO.File]::ReadAllText($credentialFile) -ceq $previous) 'Cloudflare save changed Direct Line credential'
    $dnsPrevious=$global:copilotSecretFixtureInput
    $global:copilotSecretFixtureInput='invalid token with spaces'
    $rejected=$false;try{& $helper -CredentialKind CloudflareDns > $null}catch{$rejected=$true}
    Assert-That $rejected 'Invalid Cloudflare token must be rejected'
    Assert-That ([IO.File]::ReadAllText($dnsFile) -ceq $dnsPrevious) 'Invalid input changed Cloudflare token'
    $credentialFile=$dnsFile;Verify-Access
    Write-Host 'PASS: Cloudflare token is protected, separate, redacted and preserved on invalid input'
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    Write-Host ('Elevated test process: ' + $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
} finally {
    # Delete only this uniquely named test fixture after checking its resolved workspace containment.
    $absolute = [IO.Path]::GetFullPath($fixtureRoot)
    $allowedRoot = [IO.Path]::GetFullPath((Join-Path $workspace '.local')) + [IO.Path]::DirectorySeparatorChar
    if (-not $absolute.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($absolute) -notmatch '^credential-test-[a-f0-9]{32}$') { throw 'Unsafe test cleanup target' }
    if (Test-Path -LiteralPath $absolute) { Remove-Item -LiteralPath $absolute -Recurse -Force }
}

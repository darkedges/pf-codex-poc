$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$taskDirectory = [IO.Path]::GetFullPath((Join-Path $taskRoot '.local/tool-vault/mobile'))
if (!$taskDirectory.StartsWith($taskRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid mobile custody directory' }
foreach ($taskCandidate in @($taskRoot, (Join-Path $taskRoot '.local'), (Join-Path $taskRoot '.local/tool-vault'), $taskDirectory)) {
    if ((Test-Path -LiteralPath $taskCandidate) -and ((Get-Item -LiteralPath $taskCandidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Mobile custody path cannot contain a link' }
}
[IO.Directory]::CreateDirectory($taskDirectory) | Out-Null
$taskInfo = [IO.DirectoryInfo]::new($taskDirectory)
if ($taskInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Mobile custody directory cannot be a link' }
$taskAcl = [Security.AccessControl.DirectorySecurity]::new()
$taskOwner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$taskAcl.SetOwner($taskOwner)
$taskAcl.SetAccessRuleProtection($true, $false)
foreach ($taskIdentity in @($taskOwner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $taskAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($taskIdentity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
[IO.FileSystemAclExtensions]::SetAccessControl($taskInfo, $taskAcl)
$taskVerified = [IO.FileSystemAclExtensions]::GetAccessControl($taskInfo, [Security.AccessControl.AccessControlSections]::Access)
$taskRules = @($taskVerified.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if (!$taskVerified.AreAccessRulesProtected -or $taskRules.Count -ne 2) { throw 'Mobile custody permissions could not be verified' }
foreach ($taskRule in $taskRules) {
    if ($taskRule.IdentityReference.Value -notin @($taskOwner.Value, 'S-1-5-18') -or $taskRule.AccessControlType -ne 'Allow' -or $taskRule.FileSystemRights -ne 'FullControl') { throw 'Unexpected mobile custody permissions' }
}

$ErrorActionPreference='Stop'
$workspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$directory=Join-Path $workspace '.local/tool-vault'
foreach($candidate in @($workspace,(Join-Path $workspace '.local'),$directory)){
 if((Test-Path -LiteralPath $candidate) -and ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse point in tool custody path'}
}
[IO.Directory]::CreateDirectory($directory)>$null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
$inheritance=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach($sid in @($identity.User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inheritance,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
}
[IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($directory),$acl)
$verified=[IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($directory),[Security.AccessControl.AccessControlSections]::Access)
$rules=@($verified.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if(!$verified.AreAccessRulesProtected -or $rules.Count -ne 2){throw 'Tool custody ACL verification failed'}
foreach($r in $rules){if($r.IdentityReference.Value -notin @($identity.User.Value,'S-1-5-18') -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl'){throw 'Unexpected tool custody ACL'}}
# Existing children can have explicit ACEs which parent inheritance cannot remove.
# Inspect each level before descending; never follow a junction or accept a wider file ACL.
$pending=[Collections.Generic.Stack[IO.DirectoryInfo]]::new()
$pending.Push([IO.DirectoryInfo]::new($directory))
while($pending.Count -gt 0){
 foreach($item in $pending.Pop().EnumerateFileSystemInfos()){
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse point in tool custody contents'}
  $childAcl=[IO.FileSystemAclExtensions]::GetAccessControl($item,[Security.AccessControl.AccessControlSections]::Access)
  $childRules=@($childAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if($childRules.Count -ne 2){throw 'Unexpected child custody ACL'}
  foreach($r in $childRules){if($r.IdentityReference.Value -notin @($identity.User.Value,'S-1-5-18') -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne 'FullControl'){throw 'Unexpected child custody ACL'}}
  if($item -is [IO.DirectoryInfo]){$pending.Push($item)}
 }
}

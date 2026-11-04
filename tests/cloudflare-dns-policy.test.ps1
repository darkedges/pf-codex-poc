$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/cloudflare/dns-policy.ps1')
$zoneId='0123456789abcdef0123456789abcdef'
$name='pf-a.copilot.darkedges.com'
$target='a979d27b-f2cd-45cf-aada-b44c850e3a0e.cfargotunnel.com'
Assert-CopilotZone ([pscustomobject]@{id=$zoneId;name='darkedges.com'}) $zoneId
Assert-CopilotDnsRecord ([pscustomobject]@{name=$name;type='CNAME';content=$target;proxied=$true}) $name $target
$checks=2
foreach($bad in @(
  @{id=$zoneId;name='darkedges.com.au'},
  @{id='fedcba9876543210fedcba9876543210';name='darkedges.com'}
)) {
  $rejected=$false;try{Assert-CopilotZone ([pscustomobject]$bad) $zoneId}catch{$rejected=$true}
  if(!$rejected){throw 'Wrong zone was accepted'};$checks++
}
foreach($patch in @(
  @{name='pf-a.copilot.darkedges.com.darkedges.com.au'},
  @{type='A'},
  @{content='another.cfargotunnel.com'},
  @{proxied=$false}
)) {
  $record=@{name=$name;type='CNAME';content=$target;proxied=$true}
  foreach($key in $patch.Keys){$record[$key]=$patch[$key]}
  $rejected=$false;try{Assert-CopilotDnsRecord ([pscustomobject]$record) $name $target}catch{$rejected=$true}
  if(!$rejected){throw 'Mismatched record was accepted'};$checks++
}
Write-Output "$checks Cloudflare DNS zone/record boundary checks passed."

function Assert-CopilotZone($Zone,[string]$ExpectedZoneId) {
  if($Zone.id -cne $ExpectedZoneId -or $Zone.name -cne 'darkedges.com'){throw 'Cloudflare zone must be the explicitly verified darkedges.com zone.'}
}
function Assert-CopilotDnsRecord($Record,[string]$ExpectedName,[string]$ExpectedTarget) {
  if($ExpectedName -notin @('pf-a.copilot.darkedges.com','pf-b.copilot.darkedges.com') -or $Record.name -cne $ExpectedName -or $Record.type -cne 'CNAME' -or $Record.content.TrimEnd('.') -cne $ExpectedTarget -or $Record.proxied -ne $true){throw 'Cloudflare record does not exactly match the approved hostname, tunnel and proxy setting.'}
}

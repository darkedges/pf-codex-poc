param([switch]$Create,[string]$ZoneId)
$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (!$Create) {
  [ordered]@{mode='preview-only';zone='darkedges.com';requiresVerifiedZoneId=$true;credentialSource='CLOUDFLARE_API_TOKEN process environment';tunnelId='a979d27b-f2cd-45cf-aada-b44c850e3a0e';hostnames=@('pf-a.copilot.darkedges.com','pf-b.copilot.darkedges.com');overwriteExistingRecords=$false;pfForwardingEnabled=$false;certificateOrdered=$false;explicitApprovalRequired=$true} | ConvertTo-Json -Depth 4
  return
}
if ([Environment]::MachineName -ne 'DARKEDGES') { throw 'Dedicated connector host required.' }
$privateRoot = Join-Path $workspace '.local/cloudflare-connector'
$planRoot = Join-Path $workspace '.local/cloudflare-plan'
$configuration = Join-Path $privateRoot 'config.yaml'
$tunnelId = 'a979d27b-f2cd-45cf-aada-b44c850e3a0e'
$expectedHash = '03bbb62ba4859a8851fee71931d3b05e56c8966b747fedc2eebf337954299c34'
if ((Get-FileHash -LiteralPath $configuration -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'Active configuration is not the reviewed deny-all configuration.' }
$connector = Get-Content -LiteralPath (Join-Path $privateRoot 'receipt.json') -Raw | ConvertFrom-Json
if ($connector.tunnelId -ne $tunnelId -or $connector.publicRoutesEnabled) { throw 'Unexpected dedicated connector state.' }
$health = Invoke-WebRequest -Uri http://127.0.0.1:19473/ready -TimeoutSec 5 -SkipHttpErrorCheck
if ([int]$health.StatusCode -ne 200) { throw 'Deny-all connector must be ready before DNS creation.' }
. (Join-Path $PSScriptRoot 'dns-policy.ps1')
if($ZoneId -notmatch '^[a-fA-F0-9]{32}$'){throw 'Explicit darkedges.com zone ID required.'}
$apiToken=[Environment]::GetEnvironmentVariable('CLOUDFLARE_API_TOKEN','Process')
if(!$apiToken){throw 'Approved zone-scoped Cloudflare API token required in the process environment.'}
function Invoke-CfRequest([string]$Method,[string]$Path,$Body=$null) {
  $arguments=@{Uri=('https://api.cloudflare.com/client/v4/'+$Path);Method=$Method;Headers=@{Authorization=('Bearer '+$apiToken)};TimeoutSec=15;MaximumRedirection=0;SkipHttpErrorCheck=$true}
  if($null -ne $Body){$arguments.ContentType='application/json';$arguments.Body=$Body | ConvertTo-Json -Depth 5 -Compress}
  try{$response=Invoke-WebRequest @arguments}catch{throw 'Cloudflare API connection failed; no credential or request body logged.'}
  $result=$response.Content | ConvertFrom-Json
  if([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300 -or $result.success -ne $true){throw ('Cloudflare API refused the operation: HTTP '+[int]$response.StatusCode)}
  return $result.result
}
$zone=Invoke-CfRequest 'GET' ('zones/'+$ZoneId)
Assert-CopilotZone $zone $ZoneId
$receiptPath = Join-Path $planRoot 'dns-zone-correction-receipt.json'
if (Test-Path -LiteralPath $receiptPath) { throw 'DNS receipt exists; reconcile without retrying creation.' }
$receipt = [ordered]@{
  status = 'creating-dns-only'
  createdAt = [DateTime]::UtcNow.ToString('o')
  tunnelId = $tunnelId
  zoneId = $ZoneId
  zoneName = 'darkedges.com'
  target = "$tunnelId.cfargotunnel.com"
  activeConfigSha256 = $expectedHash
  pfForwardingEnabled = $false
  certificateIssuanceVerified = $false
  routes = @(
    [ordered]@{hostname='pf-a.copilot.darkedges.com';status='planned'},
    [ordered]@{hostname='pf-b.copilot.darkedges.com';status='planned'}
  )
}
foreach($route in $receipt.routes){
  $existing=@(Invoke-CfRequest 'GET' ('zones/'+$ZoneId+'/dns_records?name='+[Uri]::EscapeDataString($route.hostname)+'&per_page=100'))
  if($existing.Count -gt 1){throw 'Ambiguous existing DNS records; no changes made.'}
  if($existing.Count -eq 1){Assert-CopilotDnsRecord $existing[0] $route.hostname $receipt.target; $route.status='existing-exact-record-verified';$route.recordId=$existing[0].id}
}
$stream = [IO.File]::Open($receiptPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $writer = [IO.StreamWriter]::new($stream); $writer.Write(($receipt | ConvertTo-Json -Depth 8)); $writer.Flush() } finally { $stream.Dispose() }
foreach ($route in $receipt.routes) {
  if($route.status -eq 'existing-exact-record-verified'){continue}
  $route.status = 'creating'
  $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8
  # Explicit verified zone endpoint; no CLI certificate zone inference, overwrite or POST retry.
  try {
    $result=Invoke-CfRequest 'POST' ('zones/'+$ZoneId+'/dns_records') @{type='CNAME';name=$route.hostname;content=$receipt.target;proxied=$true;ttl=1}
    Assert-CopilotDnsRecord $result $route.hostname $receipt.target
  } catch {
    $route.status = 'reconciliation-required'
    $receipt.status = 'reconciliation-required'
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8
    throw 'DNS creation did not confirm success. Inspect and reconcile exact records; no automatic retry or overwrite.'
  }
  $route.status = 'exact-record-confirmed-by-api'
  $route.recordId = $result.id
  $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8
}
$receipt.status = 'dns-created-pf-denied'
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8
$connector.dnsCreated = $true
$connector | Add-Member dnsReconciliationRequired $false -Force
$connector | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $privateRoot 'receipt.json') -Encoding utf8
$receipt | ConvertTo-Json -Depth 8

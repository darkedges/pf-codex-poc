param([switch]$RestartConnector)
$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$version = '2026.10.5'
$expectedSha256 = 'db4e4c413612a0916f3e1679d3caaf376f94911952d163028fb726fb2e0516a9'
$source = "https://github.com/cloudflare/cloudflared/releases/download/$version/cloudflared-windows-amd64.exe"
$toolRoot = Join-Path $workspace ".local/tools/cloudflared-$version"
$exe = Join-Path $toolRoot 'cloudflared.exe'
New-Item -ItemType Directory -Path $toolRoot -Force | Out-Null
if (!(Test-Path -LiteralPath $exe)) { Invoke-WebRequest -Uri $source -OutFile $exe -TimeoutSec 120 }
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSha256) { throw 'Official cloudflared SHA-256 mismatch; executable was not run.' }
$reportedVersion = (& $exe --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $reportedVersion -notmatch '^cloudflared version 2026\.10\.5(?:\s|$)') { throw 'Unexpected cloudflared executable version.' }
[ordered]@{version=$version;sha256=$expectedSha256;source=$source} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $toolRoot 'verified-release.json') -Encoding utf8
if (!$RestartConnector) { [ordered]@{status='verified-binary-staged';version=$reportedVersion;path=$exe;connectorRestarted=$false} | ConvertTo-Json; return }
if ([Environment]::MachineName -ne 'DARKEDGES') { throw 'Dedicated connector host required.' }
$privateRoot = Join-Path $workspace '.local/cloudflare-connector'
$receiptPath = Join-Path $privateRoot 'receipt.json'
$config = Join-Path $privateRoot 'config.yaml'
$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
$tunnelId = 'a979d27b-f2cd-45cf-aada-b44c850e3a0e'
if ($receipt.tunnelId -ne $tunnelId -or $receipt.publicRoutesEnabled -or (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant() -ne '03bbb62ba4859a8851fee71931d3b05e56c8966b747fedc2eebf337954299c34') { throw 'Expected dedicated deny-all connector configuration.' }
$validation = & $exe tunnel --config $config ingress validate 2>&1
if ($LASTEXITCODE -ne 0) { throw 'New cloudflared rejected the active configuration.' }
$previous = Get-CimInstance Win32_Process -Filter "ProcessId = $($receipt.connectorPid)" -ErrorAction Stop
if ($previous) {
  $allowedPaths = @('C:\Program Files (x86)\cloudflared\cloudflared.exe',$exe)
  if ($previous.ExecutablePath -notin $allowedPaths -or !$previous.CommandLine.Contains($tunnelId) -or !$previous.CommandLine.Contains($config)) { throw 'Recorded process ownership differs; no process stopped.' }
  $receipt | Add-Member previousConnectorPid $receipt.connectorPid -Force
  $receipt | Add-Member previousExecutablePath $previous.ExecutablePath -Force
  $receipt.status = 'upgrading-deny-all'
  $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8
  Stop-Process -Id $previous.ProcessId -ErrorAction Stop
  Wait-Process -Id $previous.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
}
if (Get-NetTCPConnection -LocalPort 19473 -State Listen -ErrorAction SilentlyContinue) { throw 'Metrics port remains occupied; no unrelated process will be stopped.' }
$childEnvironment = @{}
Get-ChildItem Env: | Where-Object Name -Like 'TUNNEL_*' | ForEach-Object { $childEnvironment[$_.Name] = $null }
$started = Start-Process -FilePath $exe -ArgumentList @('tunnel','--config',('"'+$config+'"'),'run',$tunnelId) -Environment $childEnvironment -WindowStyle Hidden -RedirectStandardOutput (Join-Path $privateRoot 'connector-2026.10.5.stdout.log') -RedirectStandardError (Join-Path $privateRoot 'connector-2026.10.5.stderr.log') -PassThru
$receipt.connectorPid = $started.Id
$receipt.connectorStartedAt = [DateTime]::UtcNow.ToString('o')
$receipt | Add-Member executablePath $exe -Force
$receipt | Add-Member cloudflaredVersion $version -Force
$receipt | Add-Member executableSha256 $expectedSha256 -Force
$receipt.status = 'connector-started-deny-all'
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8
$ready = $false
for ($attempt=0; $attempt -lt 15; $attempt++) {
  try { $response=Invoke-WebRequest -Uri http://127.0.0.1:19473/ready -TimeoutSec 2 -SkipHttpErrorCheck; if([int]$response.StatusCode -eq 200){$ready=$true;break} } catch {}
  Start-Sleep -Seconds 1
}
if ($ready) { $receipt.status='connector-ready-deny-all'; $receipt.readyVerifiedAt=[DateTime]::UtcNow.ToString('o'); $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receiptPath -Encoding utf8 }
[ordered]@{version=$reportedVersion;connectorPid=$started.Id;ready=$ready;pfForwardingEnabled=$false;configurationSource='local'} | ConvertTo-Json
if (!$ready) { throw 'Updated connector is not ready; inspect protected logs without exposing credentials.' }

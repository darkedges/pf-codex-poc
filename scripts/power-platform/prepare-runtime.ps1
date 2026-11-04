param()
$ErrorActionPreference='Stop'
$localRuntimeWorkspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localRuntimeConfig=Get-Content -LiteralPath (Join-Path $localRuntimeWorkspace 'infra/power-platform/dotnet-runtime.json') -Raw | ConvertFrom-Json
$localRuntimeRoot=[IO.Path]::GetFullPath((Join-Path $localRuntimeWorkspace ('.local/tools/dotnet-'+$localRuntimeConfig.version)))
if ($localRuntimeConfig.version -notmatch '^10\.0\.\d+$' -or -not $localRuntimeRoot.StartsWith((Join-Path $localRuntimeWorkspace '.local/tools')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid project-local runtime directory' }
$localRuntimeMarker=Join-Path $localRuntimeRoot 'installation.json'
if (Test-Path -LiteralPath $localRuntimeMarker) {
 $localRuntimeInstalled=Get-Content -LiteralPath $localRuntimeMarker -Raw | ConvertFrom-Json
 if ($localRuntimeInstalled.version -ne $localRuntimeConfig.version -or ($localRuntimeInstalled.files | ConvertTo-Json -Depth 5 -Compress) -cne ($localRuntimeConfig.files | ConvertTo-Json -Depth 5 -Compress) -or -not (Test-Path -LiteralPath (Join-Path $localRuntimeRoot 'dotnet.exe')) -or -not (Test-Path -LiteralPath (Join-Path $localRuntimeRoot ('shared/Microsoft.AspNetCore.App/'+$localRuntimeConfig.version)))) { throw 'Existing project-local runtime needs integrity review' }
 Write-Output 'Project-local .NET/ASP.NET runtime already prepared.';return
}
New-Item -ItemType Directory -Path $localRuntimeRoot -Force | Out-Null
foreach ($localRuntimeArtifact in $localRuntimeConfig.files) {
 if ($localRuntimeArtifact.name -notin @('core.zip','aspnet.zip') -or -not $localRuntimeArtifact.url.StartsWith('https://builds.dotnet.microsoft.com/dotnet/') -or $localRuntimeArtifact.sha512 -notmatch '^[a-f0-9]{128}$') { throw 'Invalid pinned Microsoft runtime artifact' }
 $localRuntimeZip=Join-Path $localRuntimeRoot $localRuntimeArtifact.name
 if (-not (Test-Path -LiteralPath $localRuntimeZip)) { Invoke-WebRequest -Uri $localRuntimeArtifact.url -OutFile $localRuntimeZip -TimeoutSec 120 }
 if ((Get-FileHash -LiteralPath $localRuntimeZip -Algorithm SHA512).Hash.ToLowerInvariant() -cne $localRuntimeArtifact.sha512) { throw 'Microsoft runtime integrity check failed' }
 $localRuntimeArchive=[IO.Compression.ZipFile]::OpenRead($localRuntimeZip)
 try { foreach ($localRuntimeEntry in $localRuntimeArchive.Entries) {
  $localRuntimeTarget=[IO.Path]::GetFullPath((Join-Path $localRuntimeRoot $localRuntimeEntry.FullName))
  if (-not $localRuntimeTarget.StartsWith($localRuntimeRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Runtime archive entry escaped intended directory' }
 }} finally { $localRuntimeArchive.Dispose() }
 [IO.Compression.ZipFile]::ExtractToDirectory($localRuntimeZip,$localRuntimeRoot,$true)
}
if (-not (Test-Path -LiteralPath (Join-Path $localRuntimeRoot 'dotnet.exe')) -or -not (Test-Path -LiteralPath (Join-Path $localRuntimeRoot ('shared/Microsoft.AspNetCore.App/'+$localRuntimeConfig.version)))) { throw 'Project-local Core/ASP.NET runtime incomplete' }
@{version=$localRuntimeConfig.version;files=$localRuntimeConfig.files} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $localRuntimeMarker
Write-Output 'Verified project-local Core/ASP.NET runtime prepared; system runtime unchanged.'

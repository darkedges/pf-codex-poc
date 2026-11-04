[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$pacWorkspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$pacManifest=Get-Content -LiteralPath (Join-Path $pacWorkspace 'infra/power-platform/pac-tool.json') -Raw | ConvertFrom-Json
if ($pacManifest.package -ne 'Microsoft.PowerApps.CLI.Tool' -or $pacManifest.version -notmatch '^\d+\.\d+\.\d+$' -or $pacManifest.url -ne ('https://api.nuget.org/v3-flatcontainer/microsoft.powerapps.cli.tool/'+$pacManifest.version+'/microsoft.powerapps.cli.tool.'+$pacManifest.version+'.nupkg')) { throw 'Invalid pinned PAC package' }
& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'prepare-runtime.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Project-local PAC runtime preparation failed' }
$pacToolRoot=Join-Path $pacWorkspace ('.local/tools/pac-'+$pacManifest.version)
$pacMarker=Join-Path $pacToolRoot 'installation.json'
if (Test-Path -LiteralPath $pacMarker) {
 $pacInstalled=Get-Content -LiteralPath $pacMarker -Raw | ConvertFrom-Json
 if ($pacInstalled.sha512 -ne $pacManifest.sha512 -or -not (Test-Path -LiteralPath (Join-Path $pacToolRoot $pacInstalled.entryPoint))) { throw 'Existing project-local PAC installation needs review' }
 Write-Output ('Project-local PAC '+$pacManifest.version+' already prepared.');return
}
New-Item -ItemType Directory -Path $pacToolRoot -Force | Out-Null
$pacPackage=Join-Path $pacToolRoot 'package.nupkg'
if (-not (Test-Path -LiteralPath $pacPackage)) { Invoke-WebRequest -Uri $pacManifest.url -OutFile $pacPackage -TimeoutSec 120 }
$pacActualHash=[Convert]::ToBase64String([Convert]::FromHexString((Get-FileHash -LiteralPath $pacPackage -Algorithm SHA512).Hash))
if ($pacActualHash -cne $pacManifest.sha512) { throw 'PAC package integrity check failed; refusing extraction or execution' }
$pacExtractRoot=[IO.Path]::GetFullPath((Join-Path $pacToolRoot 'package'))
if (Test-Path -LiteralPath $pacExtractRoot) { throw 'Incomplete extraction exists; review it rather than overwriting files' }
$pacArchive=[IO.Compression.ZipFile]::OpenRead($pacPackage)
try {
 foreach ($pacEntry in $pacArchive.Entries) {
  $pacEntryTarget=[IO.Path]::GetFullPath((Join-Path $pacExtractRoot $pacEntry.FullName))
  if (-not $pacEntryTarget.StartsWith($pacExtractRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Package entry escaped intended project-local directory' }
 }
 $pacToolSettings=@($pacArchive.Entries | Where-Object FullName -Match '^tools/net10\.0/any/DotnetToolSettings\.xml$')
 if ($pacToolSettings.Count -ne 1) { throw 'Unexpected PAC tool manifest layout' }
 $pacReader=[IO.StreamReader]::new($pacToolSettings[0].Open())
 try { [xml]$pacXml=$pacReader.ReadToEnd() } finally { $pacReader.Dispose() }
 $pacCommand=@($pacXml.DotNetCliTool.Commands.Command | Where-Object Name -eq 'pac')
 if ($pacCommand.Count -ne 1 -or $pacCommand[0].Runner -ne 'dotnet' -or $pacCommand[0].EntryPoint -notmatch '^[A-Za-z0-9._-]+\.dll$') { throw 'Unexpected PAC executable manifest' }
 $pacEntryRelative=Join-Path 'package/tools/net10.0/any' $pacCommand[0].EntryPoint
} finally { $pacArchive.Dispose() }
[IO.Compression.ZipFile]::ExtractToDirectory($pacPackage,$pacExtractRoot)
if (-not (Test-Path -LiteralPath (Join-Path $pacToolRoot $pacEntryRelative))) { throw 'PAC executable missing after verified extraction' }
@{version=$pacManifest.version;sha512=$pacManifest.sha512;entryPoint=$pacEntryRelative} | ConvertTo-Json | Set-Content -LiteralPath $pacMarker
Write-Output ('Verified and prepared project-local PAC '+$pacManifest.version+'; global tools and tenant resources unchanged.')

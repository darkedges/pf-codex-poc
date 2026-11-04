param([Parameter(Mandatory=$true)][Guid]$TenantId)
$ErrorActionPreference='Stop'
if ($TenantId -eq [Guid]::Empty) { throw 'An explicit tenant ID is required' }
$ppSignInWorkspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$ppSignInTool=Get-Content -LiteralPath (Join-Path $ppSignInWorkspace 'infra/power-platform/pac-tool.json') -Raw | ConvertFrom-Json
$ppSignInRuntime=Get-Content -LiteralPath (Join-Path $ppSignInWorkspace 'infra/power-platform/dotnet-runtime.json') -Raw | ConvertFrom-Json
$ppSignInRoot=Join-Path $ppSignInWorkspace ('.local/tools/pac-'+$ppSignInTool.version)
$ppSignInMetadata=Get-Content -LiteralPath (Join-Path $ppSignInRoot 'installation.json') -Raw | ConvertFrom-Json
$ppSignInEntry=[IO.Path]::GetFullPath((Join-Path $ppSignInRoot $ppSignInMetadata.entryPoint))
if ($ppSignInMetadata.sha512 -ne $ppSignInTool.sha512 -or -not $ppSignInEntry.StartsWith($ppSignInRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Project-local PAC installation needs verification' }
$ppSignInHost=Join-Path $ppSignInWorkspace ('.local/tools/dotnet-'+$ppSignInRuntime.version+'/dotnet.exe')
# Run this interactively in a local terminal. No passwords, client secrets or tokens are accepted by this wrapper.
& $ppSignInHost $ppSignInEntry auth create --tenant $TenantId.ToString() --name ('fc-'+$TenantId.ToString().Substring(0,8))
if ($LASTEXITCODE -ne 0) { throw 'Power Platform sign-in did not complete' }

# Hidden input, protected current-user/SYSTEM DACL, no network requests.
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot '../copilot/store-direct-line-secret.ps1') -CredentialKind CloudflareDns

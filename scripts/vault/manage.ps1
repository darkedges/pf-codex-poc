param([ValidateSet('up','setup','status','start','stop','down')][string]$Action='status')
$ErrorActionPreference='Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '../..'))
function Invoke-Step([string]$Command,[string[]]$Arguments) { & $Command @Arguments; if ($LASTEXITCODE -ne 0) { throw "Vault step failed: $Command" } }
$compose=@('compose','-f','infra/vault/compose.yaml')
switch ($Action) {
 'up' { Invoke-Step 'docker' ($compose+@('up','-d')); Invoke-Step 'node' @('scripts/vault/setup.mjs'); Invoke-Step 'node' @('scripts/vault/trust.mjs') }
 'setup' { Invoke-Step 'node' @('scripts/vault/setup.mjs'); Invoke-Step 'node' @('scripts/vault/trust.mjs') }
 'status' { Invoke-Step 'docker' ($compose+@('ps')) }
 'start' { Invoke-Step 'docker' ($compose+@('start')); Invoke-Step 'node' @('scripts/vault/setup.mjs'); Invoke-Step 'node' @('scripts/vault/trust.mjs') }
 'stop' { Invoke-Step 'docker' ($compose+@('stop')) }
 # Never remove persisted storage or operator recovery material.
 'down' { Invoke-Step 'docker' ($compose+@('down')) }
}

param([ValidateSet('up','configure','test','status','start','stop','down')][string]$Action='status')
$ErrorActionPreference = 'Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Set-Location -LiteralPath $root
function Invoke-Step([string]$Command,[string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Step failed: $Command $($Arguments[0])" }
}
$compose=@('compose','--env-file','.local/pingfederate/compose.env','-f','infra/pingfederate/compose.yaml')
switch ($Action) {
    'up' {
        if (-not (Test-Path -LiteralPath '.local/pingfederate/compose.env')) { throw 'Run npm run pf:prepare first' }
        Invoke-Step 'docker' ($compose + @('up','-d'))
        Invoke-Step 'node' @('scripts/pf/bootstrap-tls.mjs','a')
        Invoke-Step 'node' @('scripts/pf/bootstrap-tls.mjs','b')
        Invoke-Step 'node' @('scripts/pf/logging.mjs')
        # Restart readiness is checked by the TLS verifier using normal certificate verification.
        Invoke-Step 'node' @('scripts/pf/bootstrap-tls.mjs','a')
        Invoke-Step 'node' @('scripts/pf/bootstrap-tls.mjs','b')
        Invoke-Step 'node' @('scripts/pf/configure.mjs')
        Invoke-Step 'node' @('scripts/pf/configure-consent.mjs')
        Invoke-Step 'node' @('--experimental-strip-types','scripts/pf/policy-setup.ts')
    }
    'configure' {
        Invoke-Step 'node' @('scripts/pf/configure.mjs')
        Invoke-Step 'node' @('scripts/pf/configure-consent.mjs')
        Invoke-Step 'node' @('--experimental-strip-types','scripts/pf/policy-setup.ts')
    }
    'test' { Invoke-Step 'node' @('scripts/pf/test.mjs') }
    'status' { Invoke-Step 'docker' ($compose + @('ps')) }
    'start' {
        Invoke-Step 'docker' ($compose + @('start'))
        Invoke-Step 'node' @('scripts/pf/bootstrap-tls.mjs','a')
        Invoke-Step 'node' @('scripts/pf/bootstrap-tls.mjs','b')
    }
    'stop' { Invoke-Step 'docker' ($compose + @('stop')) }
    # No -v: persistent volumes, private keys and local configuration are retained.
    'down' { Invoke-Step 'docker' ($compose + @('down')) }
}

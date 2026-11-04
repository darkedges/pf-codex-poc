param([string]$ReferenceProject = 'E:\development\projects\ping\pf-par-poc')
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$local = Join-Path $root '.local/pingfederate'
New-Item -ItemType Directory -Force $local | Out-Null
function New-LocalSecret([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        [IO.File]::WriteAllText($Path, 'Fc!' + [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)))
    }
}
foreach ($name in @('admin-a-password','admin-b-password','tls-password')) { New-LocalSecret "$local/$name" }
if (-not (Test-Path -LiteralPath "$local/compose.env")) {
    $values = @{}
    foreach ($line in [IO.File]::ReadAllLines("$ReferenceProject/.env")) {
        if ($line -match '^([A-Z][A-Z0-9_]*)=(.*)$') { $values[$matches[1]] = $matches[2].Trim('"') }
    }
    $lines = foreach ($name in @('PING_IDENTITY_DEVOPS_USER','PING_IDENTITY_DEVOPS_KEY')) {
        if (-not $values[$name] -or $values[$name] -match '[\r\n]') { throw "Missing/invalid reference $name" }
        "$name=$($values[$name])"
    }
    $lines += 'PF_DOCKER_SUBNET=10.234.0.0/24'
    [IO.File]::WriteAllLines("$local/compose.env", $lines)
}
$lines=@([IO.File]::ReadAllLines("$local/compose.env") | Where-Object { $_ -notmatch '^PF_(INITIAL_PASSWORD|A_INITIAL_PASSWORD|B_INITIAL_PASSWORD)=' })
$lines += 'PF_A_INITIAL_PASSWORD=' + [IO.File]::ReadAllText("$local/admin-a-password")
$lines += 'PF_B_INITIAL_PASSWORD=' + [IO.File]::ReadAllText("$local/admin-b-password")
[IO.File]::WriteAllLines("$local/compose.env",$lines)
foreach ($name in @('localhost.pem','localhost-key.pem','ca.pem')) {
    if (-not (Test-Path -LiteralPath "$local/$name")) { Copy-Item -LiteralPath "$ReferenceProject/certs/$name" -Destination "$local/$name" }
}
if (-not (Test-Path -LiteralPath "$local/localhost.p12")) {
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile("$local/localhost.pem", "$local/localhost-key.pem")
    try {
        if ($certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) { throw 'Reference TLS certificate expired' }
        [IO.File]::WriteAllBytes("$local/localhost.p12", $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, [IO.File]::ReadAllText("$local/tls-password")))
    } finally { $certificate.Dispose() }
}
# The image bootstrap hook creates its administrator from PING_IDENTITY_PASSWORD.
# Never reuse the reference project's administration credentials.
foreach ($node in @('a','b')) {
    if (-not (Test-Path -LiteralPath "$local/bootstrap-admin-$node.json")) {
        [IO.File]::WriteAllText("$local/bootstrap-admin-$node.json", (@{ username='administrator'; password=[IO.File]::ReadAllText("$local/admin-$node-password") } | ConvertTo-Json -Compress))
    }
}
Write-Output 'Local PF preparation complete. Credentials and TLS material are in ignored .local/pingfederate; no secret values printed.'

param([switch]$SkipWeb)
$ErrorActionPreference = 'Stop'
$taskMobile = Split-Path -Parent $PSScriptRoot
$taskWorkspace = [IO.Path]::GetFullPath((Join-Path $taskMobile '../..'))
$taskJdk = Join-Path $env:ProgramFiles 'Android/Android Studio/jbr'
$taskSdk = if ($env:ANDROID_HOME -and (Test-Path -LiteralPath $env:ANDROID_HOME)) { $env:ANDROID_HOME } else { Join-Path $env:USERPROFILE 'AppData/Local/Android/Sdk' }
if (!(Test-Path -LiteralPath (Join-Path $taskJdk 'bin/java.exe')) -or !(Test-Path -LiteralPath (Join-Path $taskSdk 'platforms/android-36/android.jar'))) { throw 'Android Studio JDK 21 and Android SDK platform 36 are required.' }
$env:JAVA_HOME = $taskJdk
$env:ANDROID_HOME = $taskSdk
$env:GRADLE_USER_HOME = Join-Path $taskWorkspace '.local/mobile/gradle'
$taskSigning = Join-Path $taskWorkspace '.local/mobile/signing'
New-Item -ItemType Directory -Path $taskSigning -Force | Out-Null
# Protect only this newly dedicated local test-signing directory; no SACL read.
$taskAcl = [Security.AccessControl.DirectorySecurity]::new()
$taskAcl.SetAccessRuleProtection($true, $false)
$taskOwner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$taskAcl.SetOwner($taskOwner)
foreach ($taskIdentity in @($taskOwner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $taskRule = [Security.AccessControl.FileSystemAccessRule]::new($taskIdentity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $taskAcl.AddAccessRule($taskRule)
}
[IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($taskSigning), $taskAcl)
$taskKeystore = Join-Path $taskSigning 'debug.keystore'
if (!(Test-Path -LiteralPath $taskKeystore)) {
    # Public standard Android debug passwords; this is not a release/backend key.
    & (Join-Path $taskJdk 'bin/keytool.exe') -genkeypair -keystore $taskKeystore -storetype JKS -alias AndroidDebugKey -keyalg RSA -keysize 3072 -validity 3650 -dname 'CN=Federated Copilot Device Test,O=Local Development' -storepass android -keypass android -noprompt
    if ($LASTEXITCODE -ne 0) { throw 'Local device-test signing key generation failed.' }
}
$taskSdkValue = $taskSdk.Replace('\', '/').Replace(':', '\:')
[IO.File]::WriteAllText((Join-Path $taskMobile 'android/local.properties'), "sdk.dir=$taskSdkValue`n")
Push-Location $taskMobile
try {
    if (!$SkipWeb) { & npm run android:sync; if ($LASTEXITCODE -ne 0) { throw 'Mobile web build or Android sync failed.' } }
    Push-Location (Join-Path $taskMobile 'android')
    try {
        & ./gradlew.bat --no-daemon --no-watch-fs --console=plain --max-workers=1 :app:assembleDebug :app:testDebugUnitTest :app:lintDebug '-Pandroid.builder.sdkDownload=false' --stacktrace
        if ($LASTEXITCODE -ne 0) { throw 'Android build or verification failed.' }
    } finally { Pop-Location }
    $taskApk = Join-Path $taskMobile 'android/app/build/outputs/apk/debug/app-debug.apk'
    $taskVariant = if ($env:VITE_MOBILE_MODE -eq 'live') { 'Live-preview' } else { 'Device-test' }
    Write-Output "$taskVariant APK: $taskApk"
    Write-Output ('SHA256: ' + (Get-FileHash -LiteralPath $taskApk -Algorithm SHA256).Hash.ToLowerInvariant())
} finally { Pop-Location }

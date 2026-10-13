param([string]$SdkRoot, [string]$OutputDir)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path $PSScriptRoot -Parent
$package=Get-Content -LiteralPath (Join-Path $projectRoot 'package.json') -Raw | ConvertFrom-Json
$version=[string]$package.version
if ($version -notmatch '^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$') { throw 'package.json 版本格式无效。' }
$versionCode=[int](Get-Content -LiteralPath (Join-Path $projectRoot 'android\version-code.txt') -Raw).Trim()
if ($versionCode -lt 1) { throw 'Android versionCode 必须是正整数。' }
if (-not $SdkRoot) { $SdkRoot=$env:ANDROID_SDK_ROOT }
if (-not $SdkRoot) { $SdkRoot=$env:ANDROID_HOME }
if (-not $SdkRoot -and $env:LOCALAPPDATA) {
  $standardSdk=Join-Path $env:LOCALAPPDATA 'Android\Sdk'
  if (Test-Path -LiteralPath (Join-Path $standardSdk 'platforms\android-35\android.jar')) { $SdkRoot=$standardSdk }
}
if (-not $SdkRoot) {
  $taskWorkspace=Split-Path (Split-Path $projectRoot -Parent) -Parent
  $localSdk=Join-Path $taskWorkspace 'work\toolchains\android-sdk'
  if (Test-Path -LiteralPath (Join-Path $localSdk 'platforms\android-35\android.jar')) { $SdkRoot=$localSdk }
}
if (-not $SdkRoot) { throw '未找到 Android SDK，请设置 ANDROID_SDK_ROOT 或传入 -SdkRoot。' }
$SdkRoot=[IO.Path]::GetFullPath($SdkRoot)
$buildTools=Join-Path $SdkRoot 'build-tools\35.0.1'
$androidJar=Join-Path $SdkRoot 'platforms\android-35\android.jar'
if (-not (Test-Path -LiteralPath $androidJar) -or -not (Test-Path -LiteralPath (Join-Path $buildTools 'aapt2.exe'))) { throw '需要 Android SDK platform 35 和 build-tools 35.0.1；可通过 -SdkRoot 指定目录。' }
foreach ($command in @('javac','jar','keytool')) { Get-Command $command -ErrorAction Stop | Out-Null }
if (-not $OutputDir) { $OutputDir=Join-Path $projectRoot 'dist\android' }
$OutputDir=[IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$buildRoot=Join-Path $projectRoot ('dist\android-build\'+[Guid]::NewGuid().ToString('N'))
$assetsRoot=Join-Path $buildRoot 'assets'
$classRoot=Join-Path $buildRoot 'classes'
$dexRoot=Join-Path $buildRoot 'dex'
$generatedRoot=Join-Path $buildRoot 'generated'
foreach ($folder in @($assetsRoot,$classRoot,$dexRoot,$generatedRoot)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
Copy-Item -LiteralPath (Join-Path $projectRoot 'ui') -Destination (Join-Path $assetsRoot 'ui') -Recurse
New-Item -ItemType Directory -Path (Join-Path $assetsRoot 'core') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'core\vault.js') -Destination (Join-Path $assetsRoot 'core\vault.js')
Copy-Item -LiteralPath (Join-Path $projectRoot 'core\browser.js') -Destination (Join-Path $assetsRoot 'core\browser.js')
Copy-Item -LiteralPath (Join-Path $projectRoot 'android\bridge.js') -Destination (Join-Path $assetsRoot 'ui\android-bridge.js')
$htmlPath=Join-Path $assetsRoot 'ui\index.html'
$html=[IO.File]::ReadAllText($htmlPath)
$html=$html.Replace('</head>','<script src="./android-bridge.js"></script></head>')
[IO.File]::WriteAllText($htmlPath,$html,[Text.UTF8Encoding]::new($false))
$compiledRes=Join-Path $buildRoot 'resources.zip'
& (Join-Path $buildTools 'aapt2.exe') compile --dir (Join-Path $projectRoot 'android\res') -o $compiledRes
if ($LASTEXITCODE -ne 0) { throw 'Android 资源编译失败' }
$unsignedApk=Join-Path $buildRoot 'unsigned.apk'
& (Join-Path $buildTools 'aapt2.exe') link -I $androidJar --manifest (Join-Path $projectRoot 'android\AndroidManifest.xml') --min-sdk-version 26 --target-sdk-version 35 --version-code $versionCode --version-name $version -A $assetsRoot --java $generatedRoot -o $unsignedApk $compiledRes
if ($LASTEXITCODE -ne 0) { throw 'Android 资源链接失败' }
$javaSources=@(Get-ChildItem -LiteralPath (Join-Path $projectRoot 'android\src') -Filter '*.java' -Recurse)+@(Get-ChildItem -LiteralPath $generatedRoot -Filter '*.java' -Recurse)
$argFile=Join-Path $buildRoot 'javac-sources.txt'
$sourceLines=$javaSources | ForEach-Object { '"'+$_.FullName.Replace('\','/')+'"' }
[IO.File]::WriteAllLines($argFile,$sourceLines,[Text.UTF8Encoding]::new($false))
& javac --release 8 -encoding UTF-8 -classpath $androidJar -d $classRoot ('@'+$argFile)
if ($LASTEXITCODE -ne 0) { throw 'Android Java 编译失败' }
$classJar=Join-Path $buildRoot 'classes.jar'
& jar --create --file $classJar -C $classRoot .
if ($LASTEXITCODE -ne 0) { throw 'Java class 打包失败' }
& (Join-Path $buildTools 'd8.bat') --lib $androidJar --min-api 26 --output $dexRoot $classJar
if ($LASTEXITCODE -ne 0) { throw 'Android dex 编译失败' }
& jar --update --no-manifest --file $unsignedApk -C $dexRoot classes.dex
if ($LASTEXITCODE -ne 0) { throw 'Android dex 打包失败' }
$alignedApk=Join-Path $buildRoot 'aligned.apk'
& (Join-Path $buildTools 'zipalign.exe') -f -p 4 $unsignedApk $alignedApk
if ($LASTEXITCODE -ne 0) { throw 'Android 对齐失败' }
$privateDir=Join-Path $projectRoot 'private'
New-Item -ItemType Directory -Path $privateDir -Force | Out-Null
$signingFile=Join-Path $privateDir 'android-signing.json'
$keyStore=Join-Path $privateDir 'android-signing.jks'
if ((Test-Path -LiteralPath $keyStore) -and -not (Test-Path -LiteralPath $signingFile)) { throw '已有 Android 签名密钥但缺少签名配置，请恢复原配置以保留升级兼容性。' }
if (-not (Test-Path -LiteralPath $signingFile)) {
  $randomData=[byte[]]::new(32)
  $randomGenerator=[Security.Cryptography.RandomNumberGenerator]::Create()
  try { $randomGenerator.GetBytes($randomData) } finally { $randomGenerator.Dispose() }
  $signPassword=[Convert]::ToBase64String($randomData)
  @{password=$signPassword} | ConvertTo-Json | Set-Content -LiteralPath $signingFile -Encoding utf8
}
$signingConfig=Get-Content -LiteralPath $signingFile -Raw | ConvertFrom-Json
if (-not ($signingConfig.password -is [string]) -or -not $signingConfig.password.Length) { throw 'Android 签名配置无效。' }
$previousSignPassword=$env:VAULT_SIGN_PASSWORD
try {
$env:VAULT_SIGN_PASSWORD=$signingConfig.password
if (-not (Test-Path -LiteralPath $keyStore)) {
  & keytool -genkeypair -alias privatevault -keystore $keyStore -storepass:env VAULT_SIGN_PASSWORD -keypass:env VAULT_SIGN_PASSWORD -keyalg RSA -keysize 3072 -validity 10000 -dname 'CN=Private Vault, O=Personal'
  if ($LASTEXITCODE -ne 0) { throw 'Android 签名生成失败' }
}
$outputApk=Join-Path $OutputDir ('PrivateVault-Android-'+$version+'.apk')
& (Join-Path $buildTools 'apksigner.bat') sign --ks $keyStore --ks-key-alias privatevault --ks-pass env:VAULT_SIGN_PASSWORD --key-pass env:VAULT_SIGN_PASSWORD --out $outputApk $alignedApk
if ($LASTEXITCODE -ne 0) { throw 'Android 签名失败' }
& (Join-Path $buildTools 'apksigner.bat') verify $outputApk
if ($LASTEXITCODE -ne 0) { throw 'Android 签名验证失败' }
} finally {
  if ($null -eq $previousSignPassword) { Remove-Item Env:\VAULT_SIGN_PASSWORD -ErrorAction SilentlyContinue }
  else { $env:VAULT_SIGN_PASSWORD=$previousSignPassword }
}
Write-Output ('Android '+$version+' 安装包已生成并通过签名验证：'+$outputApk)

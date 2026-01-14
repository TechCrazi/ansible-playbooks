param(
  [string]$PfxDir = (Join-Path $PSScriptRoot '\certs'),
  [string]$WorkDir = (Join-Path $PSScriptRoot '\gd_pfx_work'),
  [int]$RenewDays = 60,
  [switch]$ForceRebuildChain = $false,
  [bool]$RotateIfGodaddyNewer = $true,
  [switch]$ForceRotateAll = $false,
  [string]$CspName = "Microsoft Enhanced RSA and AES Cryptographic Provider",
  [string]$SecretsPath = (Join-Path $PSScriptRoot 'secrets.ps1'),
  [string]$CustomerId,
  [string]$GodaddyApiKey,
  [string]$GodaddyApiSecret,
  [string]$PfxPassword
)

Set-StrictMode -Version Latest

function Read-SecretsFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path $Path)) {
    return $null
  }
  $content = Get-Content -Raw -Path $Path
  $result = @{}

  if ($Path.ToLower().EndsWith('.json') -or $content.TrimStart().StartsWith('{')) {
    $json = $content | ConvertFrom-Json
    if ($json.PSObject.Properties.Name -contains 'CustomerId') { $result.CustomerId = $json.CustomerId }
    if ($json.PSObject.Properties.Name -contains 'customer_id') { $result.CustomerId = $json.customer_id }
    if ($json.PSObject.Properties.Name -contains 'GodaddyApiKey') { $result.GodaddyApiKey = $json.GodaddyApiKey }
    if ($json.PSObject.Properties.Name -contains 'godaddy_api_key') { $result.GodaddyApiKey = $json.godaddy_api_key }
    if ($json.PSObject.Properties.Name -contains 'GodaddyApiSecret') { $result.GodaddyApiSecret = $json.GodaddyApiSecret }
    if ($json.PSObject.Properties.Name -contains 'godaddy_api_secret') { $result.GodaddyApiSecret = $json.godaddy_api_secret }
    if ($json.PSObject.Properties.Name -contains 'PfxPassword') { $result.PfxPassword = $json.PfxPassword }
    if ($json.PSObject.Properties.Name -contains 'pfx_password') { $result.PfxPassword = $json.pfx_password }
    return $result
  }

  foreach ($line in $content -split "`n") {
    if ($line -match '^\s*\$?CustomerId\s*=\s*["''](.*?)["'']') { $result.CustomerId = $Matches[1] }
    if ($line -match '^\s*\$?GodaddyApiKey\s*=\s*["''](.*?)["'']') { $result.GodaddyApiKey = $Matches[1] }
    if ($line -match '^\s*\$?GodaddyApiSecret\s*=\s*["''](.*?)["'']') { $result.GodaddyApiSecret = $Matches[1] }
    if ($line -match '^\s*\$?PfxPassword\s*=\s*["''](.*?)["'']') { $result.PfxPassword = $Matches[1] }
  }
  return $result
}

function Get-SafeFileName {
  param([Parameter(Mandatory=$true)][string]$Path)
  $name = [System.IO.Path]::GetFileName($Path)
  if ([string]::IsNullOrWhiteSpace($name)) {
    $name = $Path
  }
  return ($name -replace '[^A-Za-z0-9._-]', '_')
}

function Get-CnFromSubject {
  param([string]$Subject)
  if ($Subject -match 'CN\s*=\s*([^,]+)') {
    return $Matches[1]
  }
  return ''
}

function Get-CertificatesFromPem {
  param([Parameter(Mandatory=$true)][string]$Pem)
  $matches = [regex]::Matches($Pem, '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', [System.Text.RegularExpressions.RegexOptions]::Singleline)
  $certs = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
  foreach ($m in $matches) {
    $body = $m.Groups[1].Value -replace '\s', ''
    if (-not [string]::IsNullOrWhiteSpace($body)) {
      $bytes = [Convert]::FromBase64String($body)
      $certs.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes))
    }
  }
  return ,$certs
}

function Get-PfxCollection {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Password
  )
  $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
  $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
  $collection.Import($Path, $Password, $flags)
  return ,$collection
}

function Get-PfxLeafCertificate {
  param([Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Collection)
  $leaf = $Collection | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
  if (-not $leaf) {
    $leaf = $Collection | Select-Object -First 1
  }
  return $leaf
}

function Get-PrivateKeyForCert {
  param([Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

  $rsa = $null
  try { $rsa = $Cert.GetRSAPrivateKey() } catch {}
  if (-not $rsa) {
    try { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert) } catch {}
  }
  if (-not $rsa) {
    $rsa = $Cert.PrivateKey -as [System.Security.Cryptography.RSA]
  }
  if ($rsa) { return $rsa }

  $ecdsa = $null
  try { $ecdsa = $Cert.GetECDsaPrivateKey() } catch {}
  if (-not $ecdsa) {
    try { $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Cert) } catch {}
  }
  if (-not $ecdsa) {
    $ecdsa = $Cert.PrivateKey -as [System.Security.Cryptography.ECDsa]
  }
  return $ecdsa
}

function Write-CertToFile {
  param(
    [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
    [Parameter(Mandatory=$true)][string]$Path
  )
  $bytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
  [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function Get-StoreThumbprints {
  param([Parameter(Mandatory=$true)][string]$StorePath)
  return @(Get-ChildItem -Path $StorePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Thumbprint)
}

function Remove-StoreThumbprints {
  param(
    [Parameter(Mandatory=$true)][string]$StorePath,
    [Parameter(Mandatory=$true)][string[]]$Thumbprints
  )
  foreach ($thumb in $Thumbprints) {
    try {
      $path = Join-Path $StorePath $thumb
      if (Test-Path $path) {
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
      }
    } catch {}
  }
}

$secrets = Read-SecretsFile -Path $SecretsPath
if (-not $secrets) {
  throw "Secrets file not found: $SecretsPath. Use powershell\\secrets.ps1 or secrets.json."
}
if (-not $CustomerId) { $CustomerId = $secrets.CustomerId }
if (-not $GodaddyApiKey) { $GodaddyApiKey = $secrets.GodaddyApiKey }
if (-not $GodaddyApiSecret) { $GodaddyApiSecret = $secrets.GodaddyApiSecret }
if (-not $PfxPassword) { $PfxPassword = $secrets.PfxPassword }

if (-not $CustomerId -or -not $GodaddyApiKey -or -not $GodaddyApiSecret) {
  throw 'CustomerId, GodaddyApiKey, and GodaddyApiSecret are required.'
}
if (-not $PfxPassword) { throw 'PfxPassword is required.' }

if (-not (Test-Path $PfxDir)) {
  throw "PFX directory not found: $PfxDir"
}

if (-not (Test-Path $WorkDir)) {
  New-Item -ItemType Directory -Path $WorkDir | Out-Null
}

$pfxFiles = Get-ChildItem -Path $PfxDir -Filter '*.pfx' -File
if (-not $pfxFiles) {
  throw "No .pfx files found in $PfxDir"
}

$headers = @{ Authorization = "sso-key ${GodaddyApiKey}:${GodaddyApiSecret}" }
try {
  $gd = Invoke-RestMethod -Method Get -Uri "https://api.godaddy.com/v2/customers/$CustomerId/certificates" -Headers $headers
} catch {
  throw "GoDaddy API call failed: $($_.Exception.Message)"
}
$now = (Get-Date).ToUniversalTime()
$rotated = @()

$certutilCspArgs = @()
if (-not [string]::IsNullOrWhiteSpace($CspName)) {
  $certutilCspArgs = @('-csp', $CspName)
}

foreach ($file in $pfxFiles) {
  $status = 'PENDING'
  $detail = 'not evaluated'
  $oldCn = ''
  $oldNotAfter = $null
  $issuer = ''

  try {
    $collection = Get-PfxCollection -Path $file.FullName -Password $PfxPassword
    $leaf = Get-PfxLeafCertificate -Collection $collection
    if (-not $leaf) {
      throw "Unable to determine leaf certificate"
    }
    $issuer = $leaf.Issuer
    $oldCn = Get-CnFromSubject -Subject $leaf.Subject
    $oldNotAfter = $leaf.NotAfter.ToUniversalTime()
  } catch {
    $status = 'SKIP'
    $detail = "cert read failed: $($_.Exception.Message)"
  }

  if ($status -eq 'PENDING' -and ($issuer -notmatch '(?i)go\s*daddy|starfield')) {
    $status = 'SKIP'
    $detail = "issuer not GoDaddy/Starfield: $issuer"
  }

  $expiringSoon = $false
  if ($status -eq 'PENDING' -and $oldNotAfter) {
    $expiringSoon = ($oldNotAfter -lt $now.AddDays($RenewDays))
  }

  if ($status -eq 'PENDING' -and -not $expiringSoon -and -not $ForceRebuildChain -and -not $ForceRotateAll -and -not $RotateIfGodaddyNewer) {
    $status = 'SKIP'
    $detail = "not expiring within $RenewDays days (notAfter=$($oldNotAfter.ToString('u')))"
  }

  if ($status -eq 'PENDING' -and [string]::IsNullOrWhiteSpace($oldCn)) {
    $status = 'SKIP'
    $detail = 'CN could not be parsed'
  }

  $chosen = $null
  if ($status -eq 'PENDING') {
    $chosen = $gd.certificates | Where-Object { $_.commonName -eq $oldCn -and $_.status -eq 'ISSUED' } | Sort-Object validEndAt | Select-Object -Last 1
    if (-not $chosen) {
      $status = 'NO_NEW_CERT'
      $detail = "checked GoDaddy: no ISSUED cert found for CN=$oldCn"
    }
  }

  $eligibleByExpiry = ($expiringSoon -or $ForceRebuildChain -or $ForceRotateAll)
  if ($status -eq 'PENDING' -and $RotateIfGodaddyNewer) {
    try {
      $localDt = $oldNotAfter
      $remoteDt = [DateTimeOffset]::Parse($chosen.validEndAt, $null, [System.Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
      $godaddyNewer = ($localDt -lt $remoteDt)
      if (-not $eligibleByExpiry -and -not $godaddyNewer) {
        $status = 'SKIP'
        $detail = "GoDaddy cert not newer than local (local=$($localDt.ToString('u')), godaddy=$($chosen.validEndAt))"
      }
    } catch {
      if (-not $eligibleByExpiry) {
        $status = 'SKIP'
        $detail = 'Unable to compare expirations'
      }
    }
  }

  if ($status -eq 'PENDING') {
    try {
      $bundle = Invoke-RestMethod -Method Get -Uri "https://api.godaddy.com/v1/certificates/$($chosen.certificateId)/download" -Headers $headers
      $bundleSafe = Get-SafeFileName -Path $oldCn
      $bundlePath = Join-Path $WorkDir "${bundleSafe}_cert-bundle.json"
      $bundleJson = $bundle | ConvertTo-Json -Depth 6
      [System.IO.File]::WriteAllText($bundlePath, $bundleJson, [System.Text.Encoding]::UTF8)

      $leafCerts = Get-CertificatesFromPem -Pem $bundle.pems.certificate
      if (-not $leafCerts -or $leafCerts.Count -eq 0) {
        throw 'Downloaded leaf certificate is empty'
      }
      $newLeaf = $leafCerts[0]
      $newCn = Get-CnFromSubject -Subject $newLeaf.Subject
      if (-not [string]::IsNullOrWhiteSpace($newCn) -and ($newCn.ToLower() -ne $oldCn.ToLower())) {
        throw "Downloaded cert CN mismatch (local=$oldCn, godaddy=$newCn)"
      }

      $chainCerts = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
      if ($bundle.pems.intermediate) {
        $chainCerts.AddRange((Get-CertificatesFromPem -Pem $bundle.pems.intermediate))
      }
      if ($bundle.pems.cross) {
        $chainCerts.AddRange((Get-CertificatesFromPem -Pem $bundle.pems.cross))
      } else {
        Write-Host "Warning: No cross certificate provided by GoDaddy for CN=$oldCn (file=$($file.FullName))"
      }
      if ($bundle.pems.root) {
        $chainCerts.AddRange((Get-CertificatesFromPem -Pem $bundle.pems.root))
      }

      $outCn = $oldCn -replace '^\*','_'
      $outCn = $outCn -replace '[^A-Za-z0-9._-]','_'
      $outPath = Join-Path $PfxDir "$outCn.pfx"

      Copy-Item -Path $file.FullName -Destination "$($file.FullName).old" -Force

      $canCopy = $newLeaf.PSObject.Methods.Name -contains 'CopyWithPrivateKey'
      if (-not [string]::IsNullOrWhiteSpace($CspName)) {
        $canCopy = $false
      }
      if ($canCopy) {
        $privateKey = Get-PrivateKeyForCert -Cert $leaf
        if (-not $privateKey) {
          throw 'Private key not found on existing PFX'
        }
        if ($privateKey -is [System.Security.Cryptography.RSA]) {
          $leafWithKey = $newLeaf.CopyWithPrivateKey([System.Security.Cryptography.RSA]$privateKey)
        } elseif ($privateKey -is [System.Security.Cryptography.ECDsa]) {
          $leafWithKey = $newLeaf.CopyWithPrivateKey([System.Security.Cryptography.ECDsa]$privateKey)
        } else {
          throw 'Unsupported private key type'
        }

        $exportCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $null = $exportCollection.Add($leafWithKey)
        if ($chainCerts.Count -gt 0) {
          $exportCollection.AddRange($chainCerts)
        }
        $bytes = $exportCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $PfxPassword)
        [System.IO.File]::WriteAllBytes($outPath, $bytes)
      } else {
        $tmpDir = Join-Path $WorkDir ("tmp_" + (Get-SafeFileName -Path $oldCn) + "_" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmpDir | Out-Null

        $beforeMy = Get-StoreThumbprints -StorePath 'Cert:\CurrentUser\My'
        $beforeCA = Get-StoreThumbprints -StorePath 'Cert:\CurrentUser\CA'
        $beforeRoot = Get-StoreThumbprints -StorePath 'Cert:\CurrentUser\Root'

        try {
          $importArgs = $certutilCspArgs + @('-f', '-user', '-p', $PfxPassword, '-importpfx', $file.FullName)
          & certutil @importArgs | Out-Null
          $afterMy = Get-StoreThumbprints -StorePath 'Cert:\CurrentUser\My'
          $importedMy = $afterMy | Where-Object { $beforeMy -notcontains $_ }

          $leafFile = Join-Path $tmpDir 'leaf.cer'
          Write-CertToFile -Cert $newLeaf -Path $leafFile
          $addLeafArgs = $certutilCspArgs + @('-f', '-user', '-addstore', 'My', $leafFile)
          & certutil @addLeafArgs | Out-Null
          $newThumb = $newLeaf.Thumbprint
          $repairArgs = $certutilCspArgs + @('-user', '-repairstore', 'My', $newThumb)
          & certutil @repairArgs | Out-Null

          foreach ($cert in $chainCerts) {
            $chainFile = Join-Path $tmpDir ("chain_" + [guid]::NewGuid().ToString('N') + '.cer')
            Write-CertToFile -Cert $cert -Path $chainFile
            $store = if ($cert.Subject -eq $cert.Issuer) { 'Root' } else { 'CA' }
            $addChainArgs = $certutilCspArgs + @('-f', '-user', '-addstore', $store, $chainFile)
            & certutil @addChainArgs | Out-Null
          }

          $afterCA = Get-StoreThumbprints -StorePath 'Cert:\CurrentUser\CA'
          $afterRoot = Get-StoreThumbprints -StorePath 'Cert:\CurrentUser\Root'
          $newCA = $afterCA | Where-Object { $beforeCA -notcontains $_ }
          $newRoot = $afterRoot | Where-Object { $beforeRoot -notcontains $_ }

          $exportArgs = $certutilCspArgs + @('-user', '-exportPFX', '-p', $PfxPassword, '-chain', 'My', $newThumb, $outPath)
          & certutil @exportArgs | Out-Null
          if (-not (Test-Path $outPath)) {
            throw 'certutil export failed'
          }

          $storeCert = Get-ChildItem -Path "Cert:\CurrentUser\My\$newThumb" -ErrorAction SilentlyContinue
          if (-not $storeCert -or -not $storeCert.HasPrivateKey) {
            throw 'Failed to attach private key to new cert'
          }
        } finally {
          try { Remove-StoreThumbprints -StorePath 'Cert:\CurrentUser\My' -Thumbprints @($newThumb) } catch {}
          if ($importedMy) { Remove-StoreThumbprints -StorePath 'Cert:\CurrentUser\My' -Thumbprints $importedMy }
          if ($newCA) { Remove-StoreThumbprints -StorePath 'Cert:\CurrentUser\CA' -Thumbprints $newCA }
          if ($newRoot) { Remove-StoreThumbprints -StorePath 'Cert:\CurrentUser\Root' -Thumbprints $newRoot }
          Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
      }

      $newCheck = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
      $newCheck.Import($outPath, $PfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
      $status = 'ROTATED'
      $detail = "rebuilt PFX at $outPath (new notAfter=$($newCheck.NotAfter.ToUniversalTime().ToString('u')))"
      $rotated += "$($file.FullName) | CN=$oldCn | out=$outPath"
    } catch {
      $status = 'FAILED'
      $detail = $_.Exception.Message
    }
  }

  Write-Host "$($file.FullName) | CN=$oldCn | $status | $detail"
}

Write-Host "Rotated certs: $($rotated.Count)"
foreach ($line in $rotated) {
  Write-Host $line
}

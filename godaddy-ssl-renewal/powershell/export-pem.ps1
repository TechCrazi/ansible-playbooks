param(
  [string]$PfxDir = (Join-Path $PSScriptRoot '\certs'),
  [string]$PemDir = (Join-Path $PSScriptRoot '\pem'),
  [string]$SecretsPath = (Join-Path $PSScriptRoot 'secrets.ps1'),
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
    if ($json.PSObject.Properties.Name -contains 'PfxPassword') { $result.PfxPassword = $json.PfxPassword }
    if ($json.PSObject.Properties.Name -contains 'pfx_password') { $result.PfxPassword = $json.pfx_password }
    return $result
  }

  foreach ($line in $content -split "`n") {
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

function Convert-BytesToPem {
  param(
    [Parameter(Mandatory=$true)][byte[]]$Bytes,
    [Parameter(Mandatory=$true)][string]$Label
  )
  $base64 = [Convert]::ToBase64String([byte[]]$Bytes)
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.AppendLine("-----BEGIN $Label-----")
  for ($i = 0; $i -lt $base64.Length; $i += 64) {
    $len = [Math]::Min(64, $base64.Length - $i)
    $null = $sb.AppendLine($base64.Substring($i, $len))
  }
  $null = $sb.AppendLine("-----END $Label-----")
  return $sb.ToString()
}

function Convert-RsaParametersToPkcs1Bytes {
  param([Parameter(Mandatory=$true)][System.Security.Cryptography.RSAParameters]$Params)

  function Encode-Asn1Length {
    param([int]$Length)
    if ($Length -lt 0x80) {
      return ,([byte]$Length)
    }
    $bytes = @()
    $temp = $Length
    while ($temp -gt 0) {
      $bytes = ,([byte]($temp -band 0xFF)) + $bytes
      $temp = $temp -shr 8
    }
    return ,([byte](0x80 + $bytes.Count)) + $bytes
  }

  function Normalize-IntegerBytes {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Count -eq 0) {
      return [byte[]]@(0x00)
    }
    $i = 0
    while ($i -lt ($Bytes.Count - 1) -and $Bytes[$i] -eq 0x00) {
      $i++
    }
    $trimmed = $Bytes[$i..($Bytes.Count - 1)]
    if ($trimmed[0] -band 0x80) {
      return [byte[]](@([byte]0x00) + $trimmed)
    }
    return [byte[]]$trimmed
  }

  function Encode-Asn1Integer {
    param([byte[]]$Bytes)
    $val = [byte[]](Normalize-IntegerBytes $Bytes)
    $len = Encode-Asn1Length $val.Length
    return ,([byte]0x02) + $len + $val
  }

  $items = @(
    (Encode-Asn1Integer ([byte[]]@(0x00))),
    (Encode-Asn1Integer $Params.Modulus),
    (Encode-Asn1Integer $Params.Exponent),
    (Encode-Asn1Integer $Params.D),
    (Encode-Asn1Integer $Params.P),
    (Encode-Asn1Integer $Params.Q),
    (Encode-Asn1Integer $Params.DP),
    (Encode-Asn1Integer $Params.DQ),
    (Encode-Asn1Integer $Params.InverseQ)
  )

  $content = @()
  foreach ($item in $items) {
    $content += $item
  }
  $contentBytes = [byte[]]$content
  $len = Encode-Asn1Length $contentBytes.Length
  return [byte[]]((,([byte]0x30)) + $len + $contentBytes)
}

function Get-PrivateKeyPem {
  param([Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

  $rsa = $null
  try { $rsa = $Cert.GetRSAPrivateKey() } catch {}
  if (-not $rsa) {
    try { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert) } catch {}
  }
  if (-not $rsa) {
    $rsa = $Cert.PrivateKey -as [System.Security.Cryptography.RSA]
  }
  if ($rsa) {
    $methods = $rsa.PSObject.Methods.Name
    if ($methods -contains 'ExportRSAPrivateKey') {
      $bytes = $rsa.ExportRSAPrivateKey()
      return Convert-BytesToPem -Bytes $bytes -Label 'RSA PRIVATE KEY'
    }

    if ($methods -contains 'ExportPkcs8PrivateKey') {
      $bytes = $rsa.ExportPkcs8PrivateKey()
      return Convert-BytesToPem -Bytes $bytes -Label 'PRIVATE KEY'
    }

    $params = $rsa.ExportParameters($true)
    $bytes = Convert-RsaParametersToPkcs1Bytes -Params $params
    return Convert-BytesToPem -Bytes $bytes -Label 'RSA PRIVATE KEY'
  }

  $ecdsa = $null
  try { $ecdsa = $Cert.GetECDsaPrivateKey() } catch {}
  if (-not $ecdsa) {
    try { $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Cert) } catch {}
  }
  if (-not $ecdsa) {
    $ecdsa = $Cert.PrivateKey -as [System.Security.Cryptography.ECDsa]
  }
  if ($ecdsa) {
    $methods = $ecdsa.PSObject.Methods.Name
    if ($methods -contains 'ExportPkcs8PrivateKey') {
      $bytes = $ecdsa.ExportPkcs8PrivateKey()
      return Convert-BytesToPem -Bytes $bytes -Label 'PRIVATE KEY'
    }
  }

  return $null
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

function Get-CertChainElements {
  param(
    [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Leaf,
    [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Collection
  )
  $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
  $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
  $extra = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
  foreach ($cert in $Collection) {
    if ($cert.Thumbprint -ne $Leaf.Thumbprint) {
      $null = $extra.Add($cert)
    }
  }
  if ($extra.Count -gt 0) {
    $chain.ChainPolicy.ExtraStore.AddRange($extra)
  }
  $null = $chain.Build($Leaf)
  return $chain.ChainElements
}

$secrets = Read-SecretsFile -Path $SecretsPath
if (-not $secrets) {
  throw "Secrets file not found: $SecretsPath. Use powershell\\secrets.ps1 or secrets.json."
}
if (-not $PfxPassword) { $PfxPassword = $secrets.PfxPassword }
if (-not $PfxPassword) { throw 'PfxPassword is required.' }

if (-not (Test-Path $PfxDir)) {
  throw "PFX directory not found: $PfxDir"
}

if (-not (Test-Path $PemDir)) {
  New-Item -ItemType Directory -Path $PemDir | Out-Null
}

$pfxFiles = Get-ChildItem -Path $PfxDir -Filter '*.pfx' -File
if (-not $pfxFiles) {
  throw "No .pfx files found in $PfxDir"
}

$exports = @()

foreach ($file in $pfxFiles) {
  $status = 'PENDING'
  $detail = 'not evaluated'
  $safeBase = Get-SafeFileName -Path $file.Name
  $leafPath = Join-Path $PemDir "$safeBase`_cert.pem"
  $chainPath = Join-Path $PemDir "$safeBase`_chain.pem"
  $fullchainPath = Join-Path $PemDir "$safeBase`_fullchain.pem"
  $keyPath = Join-Path $PemDir "$safeBase`_key.pem"

  try {
    $collection = Get-PfxCollection -Path $file.FullName -Password $PfxPassword
    $leaf = Get-PfxLeafCertificate -Collection $collection
    if (-not $leaf) {
      throw "Unable to determine leaf certificate"
    }

    $leafPem = Convert-BytesToPem -Bytes $leaf.RawData -Label 'CERTIFICATE'

    $chainElements = Get-CertChainElements -Leaf $leaf -Collection $collection
    $chainPem = ''
    if ($chainElements.Count -gt 1) {
      for ($i = 1; $i -lt $chainElements.Count; $i++) {
        $chainPem += Convert-BytesToPem -Bytes $chainElements[$i].Certificate.RawData -Label 'CERTIFICATE'
      }
    }

    $fullchainPem = $leafPem + $chainPem
    $keyPem = Get-PrivateKeyPem -Cert $leaf
    if (-not $keyPem) {
      throw 'Private key export not supported for this cert'
    }

    [System.IO.File]::WriteAllText($leafPath, $leafPem, [System.Text.Encoding]::ASCII)
    [System.IO.File]::WriteAllText($chainPath, $chainPem, [System.Text.Encoding]::ASCII)
    [System.IO.File]::WriteAllText($fullchainPath, $fullchainPem, [System.Text.Encoding]::ASCII)
    [System.IO.File]::WriteAllText($keyPath, $keyPem, [System.Text.Encoding]::ASCII)

    $status = 'EXPORTED'
    $detail = 'wrote PEM files'
  } catch {
    $status = 'FAILED'
    $detail = $_.Exception.Message
  }

  $exports += [pscustomobject]@{
    file = $file.FullName
    base = $safeBase
    status = $status
    detail = $detail
  }
}

Write-Host "Exported PEM files: $($exports.Count)"
$exports | ForEach-Object { Write-Host "$($_.file) | base=$($_.base) | $($_.status) | $($_.detail)" }

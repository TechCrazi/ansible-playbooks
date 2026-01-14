Set-StrictMode -Version Latest

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

function Convert-BytesToPem {
  param(
    [Parameter(Mandatory=$true)][byte[]]$Bytes,
    [Parameter(Mandatory=$true)][string]$Label
  )
  $base64 = [Convert]::ToBase64String($Bytes)
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
      return ,([byte]0x00)
    }
    $i = 0
    while ($i -lt ($Bytes.Count - 1) -and $Bytes[$i] -eq 0x00) {
      $i++
    }
    $trimmed = $Bytes[$i..($Bytes.Count - 1)]
    if ($trimmed[0] -band 0x80) {
      return ,([byte]0x00) + $trimmed
    }
    return $trimmed
  }

  function Encode-Asn1Integer {
    param([byte[]]$Bytes)
    $val = Normalize-IntegerBytes $Bytes
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
  $len = Encode-Asn1Length $content.Length
  return ,([byte]0x30) + $len + $content
}

function Get-RsaPrivateKeyPem {
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
  return $certs
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

function Get-ExtensionText {
  param(
    [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
    [Parameter(Mandatory=$true)][string]$OidValue
  )
  $ext = $Cert.Extensions | Where-Object { $_.Oid.Value -eq $OidValue } | Select-Object -First 1
  if (-not $ext) {
    return ''
  }
  return $ext.Format($true)
}

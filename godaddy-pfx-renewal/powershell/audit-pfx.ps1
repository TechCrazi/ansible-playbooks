param(
  [string]$PfxDir = (Join-Path $PSScriptRoot '\certs'),
  [int]$WarnDays = 30,
  [string]$OutputCsv = (Join-Path $PSScriptRoot '\pfx_audit_summary.csv'),
  [switch]$WriteCsv = $true,
  [switch]$PrintSummary = $false,
  [switch]$ShowAll = $false,
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

function Get-CnFromSubject {
  param([string]$Subject)
  if ($Subject -match 'CN\s*=\s*([^,]+)') {
    return $Matches[1]
  }
  return ''
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

$secrets = Read-SecretsFile -Path $SecretsPath
if (-not $secrets) {
  throw "Secrets file not found: $SecretsPath. Use powershell\\secrets.ps1 or secrets.json."
}
if (-not $PfxPassword) { $PfxPassword = $secrets.PfxPassword }
if (-not $PfxPassword) { throw 'PfxPassword is required.' }

if (-not (Test-Path $PfxDir)) {
  throw "PFX directory not found: $PfxDir"
}

$pfxFiles = Get-ChildItem -Path $PfxDir -Filter '*.pfx' -File
if (-not $pfxFiles) {
  throw "No .pfx files found in $PfxDir"
}

$results = @()
$issues = @()
$now = (Get-Date).ToUniversalTime()

foreach ($file in $pfxFiles) {
  $item = [ordered]@{
    file_name = $file.Name
    path = $file.FullName
    cn = ''
    subject = ''
    issuer = ''
    issuer_cn = ''
    issuer_vendor = ''
    serial = ''
    not_before = ''
    not_after = ''
    days_to_exp = ''
    expired = $false
    expiring_label = ''
    sig_alg = ''
    pubkey_alg = ''
    pubkey_bits = ''
    sha1_fingerprint = ''
    sha256_fingerprint = ''
    san_dns = ''
    key_usage = ''
    ext_key_usage = ''
    basic_constraints = ''
    has_private_key = $false
    read_ok = $false
    chain_count = '0'
    chain_root_count = '0'
    chain_intermediate_count = '0'
    has_root = $false
    has_intermediate = $false
    chain_subjects = ''
    chain_issuers = ''
  }

  try {
    $collection = Get-PfxCollection -Path $file.FullName -Password $PfxPassword
    $leaf = Get-PfxLeafCertificate -Collection $collection
    if (-not $leaf) {
      throw "Unable to determine leaf certificate"
    }

    $item.read_ok = $true
    $item.has_private_key = [bool]$leaf.HasPrivateKey
    $item.subject = $leaf.Subject
    $item.issuer = $leaf.Issuer
    $item.cn = Get-CnFromSubject -Subject $leaf.Subject
    $item.issuer_cn = Get-CnFromSubject -Subject $leaf.Issuer

    if ($leaf.Issuer -match '(?i)go\s*daddy|starfield') {
      $item.issuer_vendor = 'GoDaddy'
    } else {
      $item.issuer_vendor = 'Other'
    }

    $item.serial = $leaf.SerialNumber

    $notBefore = $leaf.NotBefore.ToUniversalTime()
    $notAfter = $leaf.NotAfter.ToUniversalTime()
    $item.not_before = $notBefore.ToString('u')
    $item.not_after = $notAfter.ToString('u')

    $days = [math]::Floor(($notAfter - $now).TotalDays)
    $item.days_to_exp = $days
    $item.expired = ($notAfter -lt $now)

    if ($notAfter -lt $now.AddDays($WarnDays)) {
      $item.expiring_label = "EXPIRING_WITHIN_${WarnDays}_DAYS"
    }

    $item.sig_alg = $leaf.SignatureAlgorithm.FriendlyName
    $item.pubkey_alg = $leaf.PublicKey.Oid.FriendlyName
    $item.pubkey_bits = $leaf.PublicKey.Key.KeySize

    $item.sha1_fingerprint = $leaf.GetCertHashString()
    $sha256 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($leaf.RawData)
    $item.sha256_fingerprint = ($sha256 | ForEach-Object { $_.ToString('x2') }) -join ''

    $sanText = Get-ExtensionText -Cert $leaf -OidValue '2.5.29.17'
    if ($sanText) {
      $dnsMatches = [regex]::Matches($sanText, 'DNS Name=([^,\r\n]+)')
      $dnsNames = @()
      foreach ($m in $dnsMatches) {
        $dnsNames += $m.Groups[1].Value.Trim()
      }
      $item.san_dns = ($dnsNames | Sort-Object -Unique) -join ';'
    }

    $kuExt = $leaf.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' } | Select-Object -First 1
    if ($kuExt) {
      $ku = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]$kuExt
      $item.key_usage = $ku.KeyUsages.ToString()
    }

    $ekuExt = $leaf.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if ($ekuExt) {
      $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$ekuExt
      $ekuNames = @()
      foreach ($oid in $eku.EnhancedKeyUsages) {
        $ekuNames += $oid.FriendlyName
      }
      $item.ext_key_usage = ($ekuNames | Where-Object { $_ } | Sort-Object -Unique) -join ';'
    }

    $bcExt = $leaf.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
    if ($bcExt) {
      $bc = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$bcExt
      $pathLen = if ($bc.HasPathLengthConstraint) { $bc.PathLengthConstraint } else { 'None' }
      $item.basic_constraints = "CA=$($bc.CertificateAuthority), PathLen=$pathLen"
    }

    $chainElements = Get-CertChainElements -Leaf $leaf -Collection $collection
    $item.chain_count = $chainElements.Count

    $rootCount = 0
    $intermediateCount = 0
    if ($chainElements.Count -gt 1) {
      for ($i = 1; $i -lt $chainElements.Count; $i++) {
        $c = $chainElements[$i].Certificate
        if ($c.Subject -eq $c.Issuer) {
          $rootCount++
        } else {
          $intermediateCount++
        }
      }
    }

    $item.chain_root_count = $rootCount
    $item.chain_intermediate_count = $intermediateCount
    $item.has_root = ($rootCount -gt 0)
    $item.has_intermediate = ($intermediateCount -gt 0)

    $item.chain_subjects = ($chainElements | ForEach-Object { $_.Certificate.Subject }) -join ';'
    $item.chain_issuers = ($chainElements | ForEach-Object { $_.Certificate.Issuer }) -join ';'
  } catch {
    $item.read_ok = $false
    $issues += "$($file.FullName): $($_.Exception.Message)"
  }

  $results += [pscustomobject]$item
}

Write-Host "Scanned: $($pfxFiles.Count)"
Write-Host "Issues: $($issues.Count)"
Write-Host "Warn days: $WarnDays"

if ($issues.Count -gt 0) {
  Write-Host "Issues:"
  $issues | ForEach-Object { Write-Host "  $_" }
}

if ($ShowAll) {
  $results | Format-List | Out-String | Write-Host
}

if ($PrintSummary) {
  foreach ($item in $results) {
    Write-Host "$($item.file_name) | $($item.cn) | $($item.issuer) | $($item.days_to_exp)"
  }
}

if ($WriteCsv) {
  $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding ASCII
  Write-Host "Wrote CSV: $OutputCsv"
}

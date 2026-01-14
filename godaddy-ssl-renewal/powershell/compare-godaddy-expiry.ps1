param(
  [string]$PfxDir = (Join-Path $PSScriptRoot '\certs'),
  [string]$OutputCsv = (Join-Path $PSScriptRoot '\pfx_compare_godaddy_expiry.csv'),
  [switch]$WriteCsv = $true,
  [switch]$ShowDetails = $true,
  [switch]$ShowSkips = $false,
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

$results = @()
$readyCount = 0

foreach ($file in $pfxFiles) {
  $status = 'PENDING'
  $detail = ''
  $cn = ''
  $onPrem = ''
  $gdExp = ''
  $localDt = $null

  try {
    $collection = Get-PfxCollection -Path $file.FullName -Password $PfxPassword
    $leaf = Get-PfxLeafCertificate -Collection $collection
    if (-not $leaf) {
      throw "Unable to determine leaf certificate"
    }
    $cn = Get-CnFromSubject -Subject $leaf.Subject
    $localDt = $leaf.NotAfter.ToUniversalTime()
    $onPrem = $localDt.ToString('u')
  } catch {
    $status = 'SKIP'
    $detail = "cert read failed: $($_.Exception.Message)"
  }

  if ($status -eq 'PENDING' -and ([string]::IsNullOrWhiteSpace($cn) -or [string]::IsNullOrWhiteSpace($onPrem))) {
    $status = 'SKIP'
    $detail = 'CN or notAfter could not be parsed'
  }

  $chosen = $null
  if ($status -eq 'PENDING') {
    $chosen = $gd.certificates | Where-Object { $_.commonName -eq $cn -and $_.status -eq 'ISSUED' } | Sort-Object validEndAt | Select-Object -Last 1
    if (-not $chosen) {
      $status = 'NO_GODADDY'
      $detail = "no ISSUED GoDaddy cert found for CN=$cn"
    } else {
      $gdExp = $chosen.validEndAt
    }
  }

  if ($status -eq 'PENDING' -and $chosen) {
    try {
      $remoteDt = [DateTimeOffset]::Parse($gdExp, $null, [System.Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
      if ($localDt -lt $remoteDt) {
        $status = 'READY'
        $detail = 'GoDaddy expiry is later'
        $readyCount++
      } else {
        $status = 'NOT_READY'
        $detail = 'Local expiry is not older than GoDaddy'
      }
    } catch {
      $status = 'UNKNOWN'
      $detail = 'Unable to compare expirations'
    }
  }

  if ($status -eq 'SKIP' -and $ShowSkips) {
    Write-Host "Skipping $($file.FullName): $detail"
  }

  $results += [pscustomobject]@{
    file = $file.FullName
    cn = $cn
    on_prem_exp = $onPrem
    godaddy_exp = $gdExp
    status = $status
    detail = $detail
  }
}

Write-Host "Ready for renewal: $readyCount"

if ($ShowDetails) {
  $results | ForEach-Object {
    Write-Host "$($_.file) | $($_.cn) | $($_.status) | $($_.detail)"
  }
}

if ($WriteCsv) {
  $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding ASCII
  Write-Host "Wrote CSV: $OutputCsv"
}

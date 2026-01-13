param(
  [string]$PfxDir = (Join-Path $PSScriptRoot '\certs'),
  [string]$WorkDir = (Join-Path $PSScriptRoot '\gd_pfx_work')
)

if (-not (Test-Path $PfxDir)) {
  throw "PFX directory not found: $PfxDir"
}

if (-not (Test-Path $WorkDir)) {
  New-Item -ItemType Directory -Path $WorkDir | Out-Null
}

$oldFiles = Get-ChildItem -Path $PfxDir -Filter '*.pfx.old' -File -ErrorAction SilentlyContinue
foreach ($f in $oldFiles) {
  Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
}

$workFiles = Get-ChildItem -Path $WorkDir -File -ErrorAction SilentlyContinue
foreach ($f in $workFiles) {
  Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue
}

Write-Host "Removed old backups: $($oldFiles.Count)"
Write-Host "Cleared work dir files: $($workFiles.Count)"

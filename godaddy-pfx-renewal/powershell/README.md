# PowerShell Scripts

These scripts are the Windows-native replacements for the Ansible playbooks. They use built-in .NET + certutil and do not require Linux tools.

## Quick Start
1. Put your `.pfx` files in a folder (default: the same folder as the script + `\certs`).
2. Create `secrets.ps1` or `secrets.json` in the same folder as the scripts.
3. Run a script, for example:

```powershell
powershell -ExecutionPolicy Bypass -File .\audit-pfx.ps1
```

## Secrets File
You can use either PowerShell or JSON.

`secrets.ps1` example:
```powershell
$CustomerId = "YOUR_CUSTOMER_ID"
$GodaddyApiKey = "YOUR_GODADDY_API_KEY"
$GodaddyApiSecret = "YOUR_GODADDY_API_SECRET"
$PfxPassword = "YOUR_PFX_PASSWORD"
```

`secrets.json` example:
```json
{
  "CustomerId": "YOUR_CUSTOMER_ID",
  "GodaddyApiKey": "YOUR_GODADDY_API_KEY",
  "GodaddyApiSecret": "YOUR_GODADDY_API_SECRET",
  "PfxPassword": "YOUR_PFX_PASSWORD"
}
```

Each script accepts `-SecretsPath` and also allows CLI overrides for any secret value.

## Scripts

### audit-pfx.ps1
Reads every PFX file and outputs full certificate details. Optional CSV output.

Options:
- `-PfxDir` (default: `\certs` under script folder)
- `-WarnDays` (default: `30`)
- `-OutputCsv` (default: `pfx_audit_summary.csv` under script folder)
- `-WriteCsv` (default: enabled)
- `-PrintSummary` (print one-line summary per cert)
- `-ShowAll` (print full object details)
- `-SecretsPath` (default: `secrets.ps1`)
- `-PfxPassword` (override secrets)

Example:
```powershell
powershell -ExecutionPolicy Bypass -File .\audit-pfx.ps1 -PfxDir C:\cert-test\certs -WarnDays 60
```

### compare-godaddy-expiry.ps1
Compares each local PFX expiry against the latest ISSUED GoDaddy cert for the same CN.

Options:
- `-PfxDir` (default: `\certs` under script folder)
- `-OutputCsv` (default: `pfx_compare_godaddy_expiry.csv` under script folder)
- `-WriteCsv` (default: enabled)
- `-ShowDetails` (default: enabled)
- `-ShowSkips` (show skipped reasons)
- `-SecretsPath` (default: `secrets.ps1`)
- `-CustomerId`, `-GodaddyApiKey`, `-GodaddyApiSecret`, `-PfxPassword`

Example:
```powershell
powershell -ExecutionPolicy Bypass -File .\compare-godaddy-expiry.ps1 -PfxDir C:\cert-test\certs
```

### rotate-pfx.ps1
Downloads the latest GoDaddy cert bundle and rebuilds PFX files with full chains.
Only GoDaddy/Starfield issuers are eligible.

Options:
- `-PfxDir` (default: `\certs` under script folder)
- `-WorkDir` (default: `\gd_pfx_work` under script folder)
- `-RenewDays` (default: `60`)
- `-ForceRebuildChain` (rebuild PFX even if not expiring)
- `-RotateIfGodaddyNewer` (bool, default: `$true`; use `-RotateIfGodaddyNewer:$false` to disable)
- `-ForceRotateAll` (force all GoDaddy/Starfield PFX to rebuild)
- `-SecretsPath` (default: `secrets.ps1`)
- `-CustomerId`, `-GodaddyApiKey`, `-GodaddyApiSecret`, `-PfxPassword`

Examples:
```powershell
powershell -ExecutionPolicy Bypass -File .\rotate-pfx.ps1 -PfxDir C:\cert-test\certs
powershell -ExecutionPolicy Bypass -File .\rotate-pfx.ps1 -ForceRotateAll
powershell -ExecutionPolicy Bypass -File .\rotate-pfx.ps1 -RotateIfGodaddyNewer:$false -RenewDays 30
```

Notes:
- Creates `.pfx.old` backups before overwriting.
- Uses `certutil` and the CurrentUser certificate store to attach private keys.

### export-pem.ps1
Exports PEM files from each PFX. Produces 4 files per PFX:
`_cert.pem`, `_chain.pem`, `_fullchain.pem`, `_key.pem`.

Options:
- `-PfxDir` (default: `\certs` under script folder)
- `-PemDir` (default: `\pem` under script folder)
- `-SecretsPath` (default: `secrets.ps1`)
- `-PfxPassword` (override secrets)

Example:
```powershell
powershell -ExecutionPolicy Bypass -File .\export-pem.ps1 -PfxDir C:\cert-test\certs -PemDir C:\cert-test\pem
```

### cleanup-pfx.ps1
Removes `.pfx.old` files and clears the work directory.

Options:
- `-PfxDir` (default: `\certs` under script folder)
- `-WorkDir` (default: `\gd_pfx_work` under script folder)

Example:
```powershell
powershell -ExecutionPolicy Bypass -File .\cleanup-pfx.ps1 -PfxDir C:\cert-test\certs
```

### Common.ps1
Shared helper functions for parsing certificates. Not meant to be executed directly.

## Output Files
- `pfx_audit_summary.csv`: audit report
- `pfx_compare_godaddy_expiry.csv`: GoDaddy comparison report
- `.pfx.old`: backup files created by rotate
- `gd_pfx_work`: downloaded cert bundles and temporary files
- `pem` folder: PEM exports

## Running from a Different Folder
If your certs are not under the script folder, always pass `-PfxDir` (and `-WorkDir`/`-PemDir` as needed).

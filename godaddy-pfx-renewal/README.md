SSL Cert Ansible Playbook (GoDaddy V2 API)
================

Playbooks and task includes for auditing, comparing, and rotating local PFX files using GoDaddy API bundles.

Files
-----
- audit-pfx.yml: Audit local PFX files; writes detailed CSV `pfx_audit_summary.csv`.
- audit-pfx-task.yml: Per-file audit tasks (included by audit playbook).
- rotate-pfx.yml: Rotate eligible PFX files by downloading GoDaddy bundle and rebuilding PFX with full chain.
- rotate-pfx-task.yml: Per-file rotation tasks (included by rotation playbook).
- compare-godaddy-expiry.yml: Compare local PFX expiry to GoDaddy; writes `pfx_compare_godaddy_expiry.csv`.
- compare-godaddy-expiry-task.yml: Per-file compare tasks (included by compare playbook).
- cleanup-pfx.yml: Remove `*.pfx.old` backups and clear files from the GoDaddy work directory.
- export-pem.yml: Export PEM files from PFX into `./pem`.
- export-pem-task.yml: Per-file PEM export tasks (included by export playbook).
- audit-pfx-win.yml: Windows-target audit playbook; writes `pfx_audit_summary.csv`.
- audit-pfx-task-win.yml: Per-file Windows audit tasks (included by audit playbook).
- rotate-pfx-win.yml: Windows-target rotation playbook.
- rotate-pfx-task-win.yml: Per-file Windows rotation tasks (included by rotation playbook).
- compare-godaddy-expiry-win.yml: Windows-target compare playbook; writes `pfx_compare_godaddy_expiry.csv`.
- compare-godaddy-expiry-task-win.yml: Per-file Windows compare tasks (included by compare playbook).
- cleanup-pfx-win.yml: Windows-target cleanup playbook.
- powershell/: PowerShell-only scripts (no Ansible required).
- powershell/Common.ps1: Shared PowerShell helpers.
- powershell/audit-pfx.ps1: PowerShell audit (writes CSV).
- powershell/compare-godaddy-expiry.ps1: PowerShell compare (writes CSV).
- powershell/rotate-pfx.ps1: PowerShell rotation.
- powershell/cleanup-pfx.ps1: PowerShell cleanup.
- powershell/export-pem.ps1: PowerShell PEM export.
- powershell/secrets.sample.ps1: Template for PowerShell secrets.
- secrets.yml: Local secrets (GoDaddy customer ID, API key/secret, PFX password). Ignored by git.
- pfx_audit_summary.csv / pfx_compare_godaddy_expiry.csv: CSV outputs written by the playbooks.


Prereqs
-------
Control node (Linux/macOS/WSL):
- ansible-playbook available on the host running the playbooks.
- bash, openssl, jq, python3, mktemp, awk, sed available on the control node.
- GoDaddy API credentials with access to the customer certificates endpoint.
- For Windows playbooks: install the `ansible.windows` collection.

Windows targets (for *_windows playbooks):
- WinRM enabled and reachable.
- PowerShell 5.1+ (or PowerShell 7).
- OpenSSL installed and in PATH (used for rotation and validation).
- PFX files present on the Windows host (default `C:\certs`, override with `pfx_dir`).

PowerShell-only scripts:
- Windows PowerShell 5.1 or PowerShell 7.
- No OpenSSL/Ansible required (scripts use .NET).

Install
-------
macOS (Homebrew):
- Install Homebrew if needed: https://brew.sh
- Install dependencies:
  brew install ansible openssl jq
  ansible-galaxy collection install ansible.windows

Ubuntu/Debian (apt):
- sudo apt update
- sudo apt install -y ansible openssl jq python3
 - ansible-galaxy collection install ansible.windows

Windows (control node):
- Use WSL (recommended) and follow the Ubuntu/Debian steps above.
 - ansible-galaxy collection install ansible.windows

Windows targets (hosts):
- Install OpenSSL (Chocolatey):
  choco install openssl
- Enable WinRM:
  Enable-PSRemoting -Force
- If you use basic auth in a lab:
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'

Example inventory (windows.ini):
[windows]
winhost ansible_host=WIN_HOST_IP ansible_user=USER ansible_password=PASS ansible_connection=winrm ansible_winrm_transport=basic ansible_winrm_server_cert_validation=ignore

Secrets
-------
 - Find your GoDaddy customer_id from a shopper ID, shoppers ID can be found on GoDaddy portal (one-time lookup):
    ```bash
    # Pull Customer ID
    curl -s -X GET \
      -H "Authorization: sso-key ${API_KEY}:${API_SECRET}" \
      "https://api.godaddy.com/v1/shoppers/REPLACE_WITH_SHOPPER_ID?includes=customerId" \
    | jq .
    ```

 - Create/Edit `secrets.yml` with your values:

    ```yaml
    customer_id: "YOUR_CUSTOMER_ID"
    godaddy_api_key: "YOUR_GODADDY_API_KEY"
    godaddy_api_secret: "YOUR_GODADDY_API_SECRET"
    pfx_password: "YOUR_PFX_PASSWORD"
    ```




Usage
-----
Place PFX files in `./certs` on Linux/macOS or `C:\certs` on Windows targets (or set `pfx_dir`).

Linux/macOS (local control node):
Audit PFX files (writes CSV to `./pfx_audit_summary.csv`):
ansible-playbook -i localhost, -c local audit-pfx.yml

Optional audit vars:
- pfx_dir (default ./certs)
- warn_days (default 30)
- output_csv (default ./pfx_audit_summary.csv)
- write_csv (default true)
- print_summary (default false)
- summary_header (default false)
- show_all (default false)

Rotate PFX files (GoDaddy/Starfield issuers only, expiring within 60 days):
ansible-playbook -i localhost, -c local rotate-pfx.yml

Optional rotation vars:
- pfx_dir (default ./certs)
- work_dir (default ./gd_pfx_work)
- renew_days (default 60)
- force_rebuild_chain (default false)
- rotate_if_godaddy_newer (default false)
- pfx_strong_encryption (default false; set true to use AES-256-CBC + SHA256 for PFX)

Force rebuild of GoDaddy chain for all eligible GoDaddy/Starfield certs:
ansible-playbook -i localhost, -c local rotate-pfx.yml -e "force_rebuild_chain=true"

Rotate when GoDaddy has a newer cert (even if not expiring soon):
ansible-playbook -i localhost, -c local rotate-pfx.yml -e "rotate_if_godaddy_newer=true"

Use stronger PFX encryption (AES-256-CBC + SHA256):
ansible-playbook -i localhost, -c local rotate-pfx.yml -e "pfx_strong_encryption=true"

Cleanup old backups and work files (clears files in work_dir):
ansible-playbook -i localhost, -c local cleanup-pfx.yml

Export PEM files from PFX into `./pem`:
ansible-playbook -i localhost, -c local export-pem.yml

Optional export vars:
- pfx_dir (default ./certs)
- pem_dir (default ./pem)

PEM naming:
- Each output file is named with the full PFX filename, e.g. `mycert.pfx_cert.pem`, `mycert.pfx_chain.pem`, `mycert.pfx_fullchain.pem`, `mycert.pfx_key.pem`.

Compare local vs GoDaddy expiry (writes CSV to `./pfx_compare_godaddy_expiry.csv`):
ansible-playbook -i localhost, -c local compare-godaddy-expiry.yml

Optional compare vars:
- pfx_dir (default ./certs)
- output_csv (default ./pfx_compare_godaddy_expiry.csv)
- write_csv (default true)
- show_details (default true)
- show_skips (default false)


Examples (Linux/macOS local)
-----------------------------------------
- Audit examples (audit-pfx.yml)
  - Scans all PFX files in ./certs and writes ./pfx_audit_summary.csv.
    ```bash
    ansible-playbook -i localhost, -c local audit-pfx.yml
    ```

  - Scans a different PFX folder.
    ```bash
    ansible-playbook -i localhost, -c local audit-pfx.yml -e "pfx_dir=/path/to/pfx"
    ```

  - Marks certs expiring in 45 days or less.
    ```bash
    ansible-playbook -i localhost, -c local audit-pfx.yml -e "warn_days=45"
    ```

  - Writes the CSV report to a custom file path.
    ```bash
    ansible-playbook -i localhost, -c local audit-pfx.yml -e "output_csv=./reports/audit.csv"
    ```

  - Runs the scan but does not create a CSV file.
    ```bash
    ansible-playbook -i localhost, -c local audit-pfx.yml -e "write_csv=false"
    ```

  - Prints one summary line per cert to the console.
    ```bash
    ansible-playbook -i localhost, -c local audit-pfx.yml -e "print_summary=true"
    ```

  - Adds a header row to the console summary output.
    ```bash
    ansible-playbook -i localhost, -c local audit-pfx.yml -e "summary_header=true"
    ```

  - Prints full details for every cert to the console (large output).
    ```bash
    ansible-playbook -i localhost, -c local audit-pfx.yml -e "show_all=true"
    ```

- Rotate examples (rotate-pfx.yml)
  - Rotates GoDaddy/Starfield certs that expire within 60 days.
    ```bash
    ansible-playbook -i localhost, -c local rotate-pfx.yml
    ```

  - Only rotates certs expiring within 30 days.
    ```bash
    ansible-playbook -i localhost, -c local rotate-pfx.yml -e "renew_days=30"
    ```

  - Rebuilds PFX files even if they are not expiring (useful to fix missing chain).
    ```bash
    ansible-playbook -i localhost, -c local rotate-pfx.yml -e "force_rebuild_chain=true"
    ```

  - Rotates only when GoDaddy has a newer cert than the local file.
    ```bash
    ansible-playbook -i localhost, -c local rotate-pfx.yml -e "rotate_if_godaddy_newer=true"
    ```

  - Uses stronger PFX encryption (AES-256-CBC for key/cert, SHA-256 for integrity, 2048 PBKDF iterations).
    ```bash
    ansible-playbook -i localhost, -c local rotate-pfx.yml -e "pfx_strong_encryption=true"
    ```

  - Reads PFX files from a different folder.
    ```bash
    ansible-playbook -i localhost, -c local rotate-pfx.yml -e "pfx_dir=/path/to/pfx"
    ```

  - Uses a different temp folder for downloads and build files.
    ```bash
    ansible-playbook -i localhost, -c local rotate-pfx.yml -e "work_dir=/path/to/work"
    ```

- Compare examples (compare-godaddy-expiry.yml)
  - Compares local expiry vs GoDaddy and writes ./pfx_compare_godaddy_expiry.csv.
    ```bash
    ansible-playbook -i localhost, -c local compare-godaddy-expiry.yml
    ```

  - Compares certs from a different folder.
    ```bash
    ansible-playbook -i localhost, -c local compare-godaddy-expiry.yml -e "pfx_dir=/path/to/pfx"
    ```

  - Writes the comparison CSV to a custom file path.
    ```bash
    ansible-playbook -i localhost, -c local compare-godaddy-expiry.yml -e "output_csv=./reports/compare.csv"
    ```

  - Runs the comparison but does not write a CSV file.
    ```bash
    ansible-playbook -i localhost, -c local compare-godaddy-expiry.yml -e "write_csv=false"
    ```

  - Runs quietly (no per-cert console lines).
    ```bash
    ansible-playbook -i localhost, -c local compare-godaddy-expiry.yml -e "show_details=false"
    ```

  - Prints skipped items and the reason they were skipped.
    ```bash
    ansible-playbook -i localhost, -c local compare-godaddy-expiry.yml -e "show_skips=true"
    ```

- Export PEM examples (export-pem.yml)
  - Exports PEM files to ./pem (4 files per PFX).
    ```bash
    ansible-playbook -i localhost, -c local export-pem.yml
    ```

  - Exports from a different PFX folder.
    ```bash
    ansible-playbook -i localhost, -c local export-pem.yml -e "pfx_dir=/path/to/pfx"
    ```

  - Writes PEM files to a different output folder.
    ```bash
    ansible-playbook -i localhost, -c local export-pem.yml -e "pem_dir=./pem_out"
    ```

- Cleanup examples (cleanup-pfx.yml)
  - Deletes *.pfx.old files and clears files in ./gd_pfx_work.
    ```bash
    ansible-playbook -i localhost, -c local cleanup-pfx.yml
    ```

  - Removes backups from a different PFX folder.
    ```bash
    ansible-playbook -i localhost, -c local cleanup-pfx.yml -e "pfx_dir=/path/to/pfx"
    ```

  - Clears files in a different work folder.
    ```bash
    ansible-playbook -i localhost, -c local cleanup-pfx.yml -e "work_dir=/path/to/work"
    ```

- Windows targets:
  - Audit PFX files (writes CSV to C:\certs\pfx_audit_summary.csv by default).
    ```bash
    ansible-playbook -i windows.ini audit-pfx-win.yml
    ```

  - Rotate PFX files on the Windows host.
    ```bash
    ansible-playbook -i windows.ini rotate-pfx-win.yml
    ```

  - Rotate with stronger PFX encryption (AES-256-CBC + SHA256).
    ```bash
    ansible-playbook -i windows.ini rotate-pfx-win.yml -e "pfx_strong_encryption=true"
    ```

  - Cleanup old backups and work files on the Windows host.
    ```bash
    ansible-playbook -i windows.ini cleanup-pfx-win.yml
    ```

  - Compare local vs GoDaddy expiry (writes CSV to C:\certs\pfx_compare_godaddy_expiry.csv by default).
    ```bash
    ansible-playbook -i windows.ini compare-godaddy-expiry-win.yml
    ```

Optional Windows vars (same semantics, Windows paths):
All the -e options shown in the Linux/macOS examples above also work here; just use Windows paths like C:\certs.

- pfx_dir (default C:\certs)
- work_dir (default C:\gd_pfx_work)
- output_csv (default C:\certs\pfx_audit_summary.csv or C:\certs\pfx_compare_godaddy_expiry.csv)
- renew_days (default 60)
- force_rebuild_chain (default false)
- rotate_if_godaddy_newer (default false)
- pfx_strong_encryption (default false; set true to use AES-256-CBC + SHA256 for PFX)

PowerShell-only (no Ansible)
--------------------------------
Copy secrets template and fill it (scripts read secrets.ps1 or secrets.json, no dot-sourcing):
- powershell\secrets.sample.ps1 -> powershell\secrets.ps1

Audit (writes CSV):
powershell -ExecutionPolicy Bypass -File powershell\audit-pfx.ps1

Compare local vs GoDaddy expiry (writes CSV):
powershell -ExecutionPolicy Bypass -File powershell\compare-godaddy-expiry.ps1

Rotate PFX files:
powershell -ExecutionPolicy Bypass -File powershell\rotate-pfx.ps1

Rotate when GoDaddy has newer certs (default behavior):
powershell -ExecutionPolicy Bypass -File powershell\rotate-pfx.ps1 -RotateIfGodaddyNewer:$true

Force rotate all GoDaddy/Starfield certs (ignores expiry checks):
powershell -ExecutionPolicy Bypass -File powershell\rotate-pfx.ps1 -ForceRotateAll

Cleanup old backups and work files:
powershell -ExecutionPolicy Bypass -File powershell\cleanup-pfx.ps1

Export PEM files from PFX:
powershell -ExecutionPolicy Bypass -File powershell\export-pem.ps1

Outputs
-------
Audit CSV columns (`pfx_audit_summary.csv`):
file_name, path, cn, subject, issuer, issuer_cn, issuer_vendor, serial, not_before, not_after, days_to_exp, expired, expiring_label, sig_alg, pubkey_alg, pubkey_bits, sha1_fingerprint, sha256_fingerprint, san_dns, key_usage, ext_key_usage, basic_constraints, has_private_key, read_ok, chain_count, chain_root_count, chain_intermediate_count, has_root, has_intermediate, chain_subjects, chain_issuers

Compare CSV columns (`pfx_compare_godaddy_expiry.csv`):
file, cn, on_prem_exp, godaddy_exp, status, detail

Compare status meanings:
- READY: local cert expires earlier than GoDaddy (renewal ready)
- NOT_READY: local expiry is not older than GoDaddy
- NO_GODADDY: no ISSUED cert found for the CN
- SKIP: cert could not be read or parsed
- UNKNOWN: comparison could not be computed

Rotation notes
--------------
- Rotation rebuilds PFX using the GoDaddy bundle with intermediate and root, and includes cross cert if provided by GoDaddy.
- Set `rotate_if_godaddy_newer=true` to rotate only when GoDaddy has a newer cert than local (even if not expiring soon).
- A summary of rotated certs is printed at the end of `rotate-pfx.yml` and `rotate-pfx-win.yml`.

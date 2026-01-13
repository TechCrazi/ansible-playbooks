IISCert-ansible
================

Playbooks and task includes for auditing, comparing, and rotating local PFX files using GoDaddy API bundles.

Files
-----
- ansible_audit_pfx.yml: Audit local PFX files; writes detailed CSV `pfx_audit_summary.csv`.
- pfx_audit_item.yml: Per-file audit tasks (included by audit playbook).
- ansible_rotate_pfx.yml: Rotate eligible PFX files by downloading GoDaddy bundle and rebuilding PFX with full chain.
- pfx_rotate_item.yml: Per-file rotation tasks (included by rotation playbook).
- ansible_compare_godaddy_expiry.yml: Compare local PFX expiry to GoDaddy; writes `pfx_compare_godaddy_expiry.csv`.
- pfx_compare_item.yml: Per-file compare tasks (included by compare playbook).
- ansible_cleanup_pfx.yml: Remove `*.pfx.old` backups and clear files from the GoDaddy work directory.
- ansible_audit_pfx_windows.yml: Windows-target audit playbook; writes `pfx_audit_summary.csv`.
- pfx_audit_item_windows.yml: Per-file Windows audit tasks (included by audit playbook).
- ansible_rotate_pfx_windows.yml: Windows-target rotation playbook.
- pfx_rotate_item_windows.yml: Per-file Windows rotation tasks (included by rotation playbook).
- ansible_compare_godaddy_expiry_windows.yml: Windows-target compare playbook; writes `pfx_compare_godaddy_expiry.csv`.
- pfx_compare_item_windows.yml: Per-file Windows compare tasks (included by compare playbook).
- ansible_cleanup_pfx_windows.yml: Windows-target cleanup playbook.
- secrets.yml: Local secrets (GoDaddy customer ID, API key/secret, PFX password). Ignored by git.
- pfx_audit_summary.csv / pfx_compare_godaddy_expiry.csv: CSV outputs written by the playbooks.
- .gitignore: excludes `secrets.yml`.

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
Edit `secrets.yml` with your values:
---
customer_id: "..."
godaddy_api_key: "..."
godaddy_api_secret: "..."
pfx_password: "..."

Usage
-----
Place PFX files in `./certs` on Linux/macOS or `C:\certs` on Windows targets (or set `pfx_dir`).

Linux/macOS (local control node):
Audit PFX files (writes CSV to `./pfx_audit_summary.csv`):
ansible-playbook -i localhost, -c local ansible_audit_pfx.yml

Optional audit vars:
- pfx_dir (default ./certs)
- warn_days (default 30)
- output_csv (default ./pfx_audit_summary.csv)
- write_csv (default true)
- print_summary (default false)
- summary_header (default false)
- show_all (default false)

Rotate PFX files (GoDaddy/Starfield issuers only, expiring within 60 days):
ansible-playbook -i localhost, -c local ansible_rotate_pfx.yml

Optional rotation vars:
- pfx_dir (default ./certs)
- work_dir (default ./gd_pfx_work)
- renew_days (default 60)
- force_rebuild_chain (default false)
- rotate_if_godaddy_newer (default false)

Force rebuild of GoDaddy chain for all eligible GoDaddy/Starfield certs:
ansible-playbook -i localhost, -c local ansible_rotate_pfx.yml -e "force_rebuild_chain=true"

Rotate when GoDaddy has a newer cert (even if not expiring soon):
ansible-playbook -i localhost, -c local ansible_rotate_pfx.yml -e "rotate_if_godaddy_newer=true"

Cleanup old backups and work files (clears files in work_dir):
ansible-playbook -i localhost, -c local ansible_cleanup_pfx.yml

Compare local vs GoDaddy expiry (writes CSV to `./pfx_compare_godaddy_expiry.csv`):
ansible-playbook -i localhost, -c local ansible_compare_godaddy_expiry.yml

Optional compare vars:
- pfx_dir (default ./certs)
- output_csv (default ./pfx_compare_godaddy_expiry.csv)
- write_csv (default true)
- show_details (default true)
- show_skips (default false)

Windows targets:
Audit PFX files (writes CSV to `C:\certs\pfx_audit_summary.csv` by default):
ansible-playbook -i windows.ini ansible_audit_pfx_windows.yml

Rotate PFX files:
ansible-playbook -i windows.ini ansible_rotate_pfx_windows.yml

Cleanup old backups and work files:
ansible-playbook -i windows.ini ansible_cleanup_pfx_windows.yml

Compare local vs GoDaddy expiry (writes CSV to `C:\certs\pfx_compare_godaddy_expiry.csv` by default):
ansible-playbook -i windows.ini ansible_compare_godaddy_expiry_windows.yml

Optional Windows vars (same semantics, Windows paths):
- pfx_dir (default C:\certs)
- work_dir (default C:\gd_pfx_work)
- output_csv (default C:\certs\pfx_audit_summary.csv or C:\certs\pfx_compare_godaddy_expiry.csv)
- renew_days (default 60)
- force_rebuild_chain (default false)
- rotate_if_godaddy_newer (default false)

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
- A summary of rotated certs is printed at the end of `ansible_rotate_pfx.yml` and `ansible_rotate_pfx_windows.yml`.

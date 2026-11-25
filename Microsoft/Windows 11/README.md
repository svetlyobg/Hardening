# Windows 11 hardening

Registry-based, so it also works on **Windows Home** (no gpedit / LGPO required).

```powershell
.\Run-Hardening.ps1                                  # Audit only, changes nothing
.\Run-Hardening.ps1 -Mode Apply -Severity CAT1,CAT2 -WhatIf   # preview
.\Run-Hardening.ps1 -Mode Apply -Severity CAT1,CAT2  # as Administrator; saves a backup first
.\Run-Hardening.ps1 -Mode Rollback -BackupFile ..\Common\backup-<date>.json
```

## Files
| File | What |
|---|---|
| `stig-settings.csv` | Generated from the DISA **Windows 11 STIG V2R11**. Id = V-ID, StigId = `WN11-...`. Only unambiguous HKLM registry rules (exact value). |
| `stig-needs-review.csv` | STIG rules that were **not** automated and why (audit policy, user rights, services, ranges like "or greater", conditional/NA, per-user HKCU). Do these by hand or with LGPO/secedit/auditpol. |
| `custom-settings.csv` | Extra hardening not in the STIG (LLMNR, SMB1 ...). Edit freely. |

## Policy rules (audit policy, password/lockout policy, user rights)
Needs an **elevated** PowerShell, even for Audit. Works on Home (uses `auditpol` and `secedit`).
```powershell
.\Run-Hardening.ps1 -Policy                                   # audit only (Audit + Account types)
.\Run-Hardening.ps1 -Policy -Mode Apply -PolicyType Audit -WhatIf
.\Run-Hardening.ps1 -Policy -Mode Apply -PolicyType Audit     # start here: it is the safest
.\Run-Hardening.ps1 -Policy -Mode Rollback -BackupDir ..\Common\policy-backup-<date>
```
`policy-settings.csv` (generated, 76 rules) has three types:
- **Audit** (43): advanced audit policy. Apply only switches on what is missing, never turns anything off.
- **Account** (11): password history/length/age/complexity, lockout, guest account, anonymous SID translation.
- **Right** (22): user rights, exact match. **Not included by default** - request with `-PolicyType Right`.
  e.g. `Access this computer from the network` = Administrators + Remote Desktop Users only, which stops normal users
  reaching your shared folders, and `Allow log on locally` = Administrators + Users.
- Lockout threshold 3 locks the account after 3 wrong passwords. Min length 14 applies to the next password change.
- `policy-needs-review.csv`: Deny-rights, rules with non-standard accounts, etc.
- Every Apply first saves `audit.csv` (auditpol) and `secpol.inf` (secedit export) in `..\Common\policy-backup-<date>`.
- Audit subcategory names are the English `auditpol` names.

## Updating to a newer STIG
```powershell
..\Common\Convert-StigToCsv.ps1       -XccdfFile <...Manual-xccdf.xml> -OutDir . -Prefix stig   # registry rules
..\Common\Convert-StigPolicyToCsv.ps1 -XccdfFile <...Manual-xccdf.xml> -OutDir .                # audit/account/rights
```
Then `git diff` shows exactly which rules changed.

## Caveats
- Keys under `...\Policies\...` are always written, but some are only honoured by Pro/Enterprise.
- Test in a VM first. `LmCompatibilityLevel=5` and SMB signing can break access to old NAS/SMB shares.
- A missing value is reported as `DIFF` even when Windows defaults to the safe setting; Apply then sets it explicitly.

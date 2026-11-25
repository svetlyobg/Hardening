# Windows Server 2025 hardening

Same engine as Windows 11 (`..\Common\Invoke-RegistryHardening.ps1`).

```powershell
.\Run-Hardening.ps1                                           # Audit only
.\Run-Hardening.ps1 -Mode Apply -Severity CAT1,CAT2 -WhatIf   # preview
.\Run-Hardening.ps1 -Mode Apply -Severity CAT1,CAT2           # as Administrator
```

## Files
| File | What |
|---|---|
| `stig-settings.csv` | Generated from the DISA **Windows Server 2025 STIG V1R4** (`WN25-...`). Unambiguous HKLM registry rules only. |
| `stig-needs-review.csv` | Rules not automated, with the reason (audit policy, user rights, DC-only, conditional, ranges...). |
| `custom-settings.csv` | Extra server rules not in the STIG (RDP NLA, admin shares ...). `SRV-06` can break backup/management tools - review first. |

## Policy rules (audit policy, password/lockout policy, user rights)
Elevated PowerShell required, even for Audit. `policy-settings.csv` has 72 rules (39 Audit, 8 Account, 25 Right).
```powershell
.\Run-Hardening.ps1 -Policy                                 # member / standalone server rules, audit only
.\Run-Hardening.ps1 -Policy -Role DC                        # domain controller rules (`-DC-` in the STIG id)
.\Run-Hardening.ps1 -Policy -Mode Apply -PolicyType Audit -WhatIf
```
- User rights (`-PolicyType Right`) are never included unless you ask: a wrong list can lock out RDP, SMB or local logon.
- `policy-needs-review.csv`: Deny-rights, Hyper-V "Virtual Machines" account, "Add workstations to domain" etc.
- Backups and rollback work the same as on Windows 11 (see its README).

- Update the STIG with `..\Common\Convert-StigToCsv.ps1` and `..\Common\Convert-StigPolicyToCsv.ps1` (see the Windows 11 README).
- Other Domain Controller specifics (LDAP server signing, Kerberos policy) are in the needs-review lists.
- Works on Server 2022 for the shared rules, but its STIG has different V-IDs; generate its own CSV with the converter.
- Test on a non-production server first.

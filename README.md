# Hardening

**2026**

[Security Content Application Protocols SCC 5.14.1 Windows](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-5.14.1_Windows_bundle.zip)
[Microsoft Windows 11 STIG - Ver 2, Rel 11](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip)
[Microsoft Windows Server 2025 STIG - Ver 1, Rel 4](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2025_V1R4_STIG.zip)
[Microsoft Windows 11 STIG SCAP Benchmark - Ver 2, Rel 8](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.zip)

## New: automated hardening for Windows 11 and Windows Server 2025

PowerShell scripts generated from the official DISA STIGs (**Windows 11 V2R11**, **Windows Server 2025 V1R4**).
They need no gpedit/LGPO, so they also work on **Windows Home**. Nothing from the older folders was changed or removed.

### Is this destructive?
**Not by default, and it is designed to be reversible.**
- The default mode is **`Audit`**: it only *reads* your settings and prints what differs from the STIG. It changes nothing.
- **`-WhatIf`** shows exactly what `Apply` would change, without changing it.
- Every `Apply` first saves a **backup**, and **`Rollback`** restores it.
- Audit-policy changes only *switch logging on* and never turn anything off.
- **User rights** (the riskiest type) are **never** included unless you explicitly ask with `-PolicyType Right`.

It is still security hardening, so be sensible: stricter settings (SMB signing, NTLMv2-only, lockout after 3 bad passwords,
14-character passwords) can break access to old NAS devices or older software. **Run Audit first, try Apply in a VM or on a
test machine, and read the per-OS README.** The `Apply` and `Rollback` paths are new and were verified by unit tests of the
comparison logic plus a live read-only Audit on Windows 11 Pro; they have not yet been exercised on a wide range of machines.

### Folder structure
```
Hardening/
├── Microsoft/
│   ├── Common/                          shared engines + STIG converters (used by both OS folders)
│   │   ├── Invoke-RegistryHardening.ps1   registry rules: Audit | Apply | Rollback
│   │   ├── Invoke-PolicyHardening.ps1     audit policy, password/lockout policy, user rights (auditpol + secedit)
│   │   ├── Convert-StigToCsv.ps1          STIG XML -> registry rules CSV
│   │   └── Convert-StigPolicyToCsv.ps1    STIG XML -> audit/account/rights CSV
│   ├── Windows 11/                      NEW
│   │   ├── Run-Hardening.ps1              the one script you run
│   │   ├── stig-settings.csv              registry rules from the STIG (V-ID, severity, path, value)
│   │   ├── stig-needs-review.csv          STIG rules NOT automated, with the reason
│   │   ├── policy-settings.csv            audit / account / user-right rules from the STIG
│   │   ├── policy-needs-review.csv        policy rules NOT automated, with the reason
│   │   ├── custom-settings.csv            extra rules that are not in the STIG - edit freely
│   │   └── README.md
│   ├── Windows Server 2025/             NEW, same layout (adds -Role Member|DC for domain controllers)
│   ├── Windows 10/                      unchanged: original per-finding .ps1 / .bat scripts
│   ├── Windows Defender Antivirus/      unchanged
│   └── MS Office/                       unchanged
└── files/                             unchanged: STIG viewer, LGPO, CIS-CAT, older benchmark zips
```

### Quick start (run PowerShell as Administrator for `-Policy`)
```powershell
cd "Microsoft\Windows 11"
.\Run-Hardening.ps1                                   # registry rules, report only
.\Run-Hardening.ps1 -Policy                           # audit policy + password policy, report only
.\Run-Hardening.ps1 -Policy -Mode Apply -PolicyType Audit -WhatIf    # preview
.\Run-Hardening.ps1 -Policy -Mode Apply -PolicyType Audit            # apply (backs up first)
```
Use `powershell -NoProfile -ExecutionPolicy Bypass -File .\Run-Hardening.ps1 ...` if script execution is blocked.
More detail, including Rollback, is in `Microsoft/Windows 11/README.md` and `Microsoft/Windows Server 2025/README.md`.

### Updating to a newer STIG
Download the new STIG zip, extract the `...Manual-xccdf.xml`, and run the two converters in `Microsoft/Common/`. `git diff` then shows exactly which rules changed.


![GitHub all releases](https://img.shields.io/github/downloads/svetlyobg/Hardening/total?logo=GitHub&style=flat-square)
![GitHub repo size](https://img.shields.io/github/repo-size/svetlyobg/Hardening)
![GitHub top language](https://img.shields.io/github/languages/top/svetlyobg/Hardening)
![GitHub language count](https://img.shields.io/github/languages/count/svetlyobg/Hardening)
![GitHub pull requests](https://img.shields.io/github/issues-pr/svetlyobg/Hardening)
![GitHub issues](https://img.shields.io/github/issues/svetlyobg/Hardening)
![Twitter Follow](https://img.shields.io/twitter/follow/svkosev?style=social)

Updated Links 2025! [SCAP 1.3 Content](https://www.cyber.mil/stigs/SCAP)| [Stigs](https://stigviewer.com/stigs) | [https://stigviewer.com/](https://stigviewer.com/)

1. Check this [Amazing YouTube Tutorial](https://youtu.be/6ehIeAxzXSY) and visit the [website](https://public.cyber.mil/stigs/) to download updated versions of the files below
2. Download the [SCAP Compliance Checker](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-5.4.2_Windows_bundle.zip) for Windows
3. Download the [Microsoft Windows 10 STIG Benchmark](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V2R2_STIG_SCAP_1-2_Benchmark.zip)
4. Download the [Group Policy Objects](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_July_2021.zip)
5. Download the [Windows 10 Manual Benchmarks](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V2R2_STIG.zip)
6. Download the [standalone option for the STIG viewer](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIGViewer_2-15_Win64.zip), the [.msi file](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIGViewer_2-15_Win64.msi.zip) or the [JDK/JRE version](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIGViewer_2-15.zip)
7. Download the [Microsoft Security Compliance Toolkit (LGPO.zip only)](https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip)
8. You can check for more manual STIGS/xml benchmarks [here](https://www.stigviewer.com/stigs)
9. You can always perform fast checks using the benchmark software from the [Center for Internet Security](https://learn.cisecurity.org/cis-cat-lite)

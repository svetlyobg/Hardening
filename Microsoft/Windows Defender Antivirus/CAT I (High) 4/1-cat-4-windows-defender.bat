rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75147
rem V-75147 - Windows Defender AV must be configured to block the Potentially Unwanted Application (PUA) feature
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v PUAProtection /t REG_DWORD /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75153
rem V-75153 - Windows Defender AV must be configured to run and scan for malware and other potentially unwanted software
rem manual check - should be disabled if there is another AV installed
rem PowerShell -> Uninstall-WindowsFeature -Name Windows-Defender
rem reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75241
rem V-75241 - Windows Defender AV spyware definition age must not exceed 7 dayss
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v ASSignatureDue /t REG_DWORD /d 7 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75241
rem V-75241 - Windows Defender AV spyware definition age must not exceed 7 dayss
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v AVSignatureDue /t REG_DWORD /d 7 /f
rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75147
rem V-75147 - Windows Defender AV must be configured to block the Potentially Unwanted Application (PUA) feature
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v PUAProtection /t REG_DWORD /d 1 /f

rem V-228460 - Permit download of content from safe zones must be configured
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228460

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail /v UnblockSafeZone /t REG_DWORD /d 1 /f
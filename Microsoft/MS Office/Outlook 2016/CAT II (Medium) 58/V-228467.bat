rem V-228467 - Outlook must be configured to force authentication when connecting to an Exchange server
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228467

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v AuthenticationService /t REG_DWORD /d 16 /f
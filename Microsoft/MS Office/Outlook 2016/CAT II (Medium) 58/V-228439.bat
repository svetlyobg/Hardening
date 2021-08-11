rem V-228439 - Outlook Security Mode must be configured to use Group Policy settings
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228439

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v AdminSecurityMode /t REG_DWORD /d 3 /f
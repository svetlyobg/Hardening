rem V-228436 - The Add-In Trust Level must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228436

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v AddinTrust /t REG_DWORD /d 1 /f
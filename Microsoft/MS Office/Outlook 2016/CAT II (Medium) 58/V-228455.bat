rem V-228455 - Send all signed messages as clear signed messages must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228455

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v ClearSign /t REG_DWORD /d 1 /f
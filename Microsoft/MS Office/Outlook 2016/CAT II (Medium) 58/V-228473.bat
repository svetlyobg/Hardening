rem V-228473 - Outlook must be configured not to prompt users to choose security settings if default settings fail
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228473
rem Check to prompt the user to choose security settings if default settings fail; uncheck to automatically select

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v ForceDefaultProfile /t REG_DWORD /d 0 /f
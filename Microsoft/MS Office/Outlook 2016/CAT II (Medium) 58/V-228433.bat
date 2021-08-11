rem V-228433 - Outlook Object Model scripts must be disallowed to run for shared folders
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228433

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v SharedFolderScript /t REG_DWORD /d 0 /f
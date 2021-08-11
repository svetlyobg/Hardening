rem V-228434 - Outlook Object Model scripts must be disallowed to run for public folders
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228434

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v PublicFolderScript /t REG_DWORD /d 0 /f
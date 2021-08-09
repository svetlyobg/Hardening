@echo off

rem V-228440 - Level 1 file extensions must be blocked and not removed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228440
rem User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Attachment Security "Display Level 1 attachments" is set to "Disabled".

reg add HKCU\Software\Policies\Microsoft\Office\12.0\outlook\security /v ShowLevel1Attach /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Office\13.0\outlook\security /v ShowLevel1Attach /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Office\14.0\outlook\security /v ShowLevel1Attach /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Office\15.0\outlook\security /v ShowLevel1Attach /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v ShowLevel1Attach /t REG_DWORD /d 0 /f
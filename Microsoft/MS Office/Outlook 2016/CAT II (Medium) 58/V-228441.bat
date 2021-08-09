@echo off

rem V-228441 - Level 1 file extensions must be blocked and not removed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228441
rem Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Attachment Security "Remove file extensions blocked as Level 1" is set to "Disabled".

reg delete HKCU\Software\Policies\Microsoft\Office\12.0\outlook\security\FileExtensionsRemoveLevel1 /f
reg delete HKCU\Software\Policies\Microsoft\Office\13.0\outlook\security\FileExtensionsRemoveLevel1 /f
reg delete HKCU\Software\Policies\Microsoft\Office\14.0\outlook\security\FileExtensionsRemoveLevel1 /f
reg delete HKCU\Software\Policies\Microsoft\Office\15.0\outlook\security\FileExtensionsRemoveLevel1 /f
reg delete HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security\FileExtensionsRemoveLevel1 /f
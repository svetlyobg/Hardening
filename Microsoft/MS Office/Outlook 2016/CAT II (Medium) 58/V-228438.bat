rem V-228438 - Users customizing attachment security settings must be prevented
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228438

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook /v DisallowAttachmentCustomization /t REG_DWORD /d 1 /f
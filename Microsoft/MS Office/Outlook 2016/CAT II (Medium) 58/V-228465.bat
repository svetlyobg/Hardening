rem V-228465 - Hyperlinks in suspected phishing email messages must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228465

reg add HKCU\Software\Policies\Microsoft\Office\16.0\options\mail /v JunkMailEnableLinks /t REG_DWORD /d 0 /f
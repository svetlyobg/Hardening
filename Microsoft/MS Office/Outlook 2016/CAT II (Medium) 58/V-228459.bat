rem V-228459 - Automatic download content for email in Safe Senders list must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228459

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail /v UnblockSpecificSenders /t REG_DWORD /d 0 /f
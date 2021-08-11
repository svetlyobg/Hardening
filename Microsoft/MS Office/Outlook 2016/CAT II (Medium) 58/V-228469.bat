rem V-228469 - Automatic download of Internet Calendar appointment attachments must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228469

reg add HKCU\Software\Policies\Microsoft\Office\16.0\options\webcal /v EnableAttachments /t REG_DWORD /d 0 /f
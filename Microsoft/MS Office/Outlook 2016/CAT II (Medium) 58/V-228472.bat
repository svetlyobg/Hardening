rem V-228472 - Automatically downloading enclosures on RSS must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228472
rem This policy setting allows you to control whether Outlook automatically downloads enclosures on RSS items. If you enable this policy setting, Outlook will automatically download enclosures on RSS items. If you disable or do not configure this policy setting, enclosures on RSS items are not downloaded by default. 

reg add HKCU\Software\Policies\Microsoft\Office\12.0\outlook\options\rss /v EnableAttachments /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Office\13.0\outlook\options\rss /v EnableAttachments /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Office\14.0\outlook\options\rss /v EnableAttachments /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Office\15.0\outlook\options\rss /v EnableAttachments /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\rss /v EnableAttachments /t REG_DWORD /d 0 /f
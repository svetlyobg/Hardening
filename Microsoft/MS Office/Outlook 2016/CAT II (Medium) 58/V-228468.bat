rem V-228468 - Disabling download full text of articles as HTML must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228468

reg add HKCU\Software\Policies\Microsoft\Office\16.0\options\rss /v EnableFullTextHTML /t REG_DWORD /d 0 /f
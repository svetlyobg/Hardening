rem V-228432 - Access restriction settings for published calendars must be configured
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228432

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal /v RestrictedAccessOnly /t REG_DWORD /d 1 /f
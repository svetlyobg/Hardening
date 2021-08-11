rem V-228461 - IE Trusted Zones assumed trusted must be blocked
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228461

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail /v TrustedZone /t REG_DWORD /d 0 /f
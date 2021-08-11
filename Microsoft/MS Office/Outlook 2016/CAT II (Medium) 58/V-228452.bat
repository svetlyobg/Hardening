rem V-228452 - S/Mime interoperability with external clients for message handling must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228452

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v ExternalSMime /t REG_DWORD /d 0 /f
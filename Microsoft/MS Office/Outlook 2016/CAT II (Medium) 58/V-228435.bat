rem V-228435 - ActiveX One-Off forms must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228435

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v AllowActiveXOneOffForms /t REG_DWORD /d 0 /f
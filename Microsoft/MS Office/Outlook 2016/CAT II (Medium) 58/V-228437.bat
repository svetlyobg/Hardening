rem V-228437 - The remember password for internet e-mail accounts must be disabled
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228437

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v EnableRememberPwd /t REG_DWORD /d 0 /f
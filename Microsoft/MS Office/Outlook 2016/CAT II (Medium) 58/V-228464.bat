rem V-228464 - Always warn on untrusted macros must be enforced
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228464

reg add HKCU\Software\Policies\Microsoft\Office\16.0\security /v Level /t REG_DWORD /d 3 /f
rem V-228462 - Internet with Safe Zones for Picture Download must be disabled
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228462

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail /v Intranet /t REG_DWORD /d 0 /f
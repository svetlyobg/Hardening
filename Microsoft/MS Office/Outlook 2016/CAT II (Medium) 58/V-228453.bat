rem V-228453 - Message formats must be set to use SMime
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228453

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v MsgFormats /t REG_DWORD /d 1 /f
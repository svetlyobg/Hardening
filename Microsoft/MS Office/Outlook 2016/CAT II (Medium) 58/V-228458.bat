rem V-228458 - External content and pictures in HTML email must be displayed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228458

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail /v BlockExtContent /t REG_DWORD /d 1 /f
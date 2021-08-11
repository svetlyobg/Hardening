rem V-228430 - Publishing to a Web Distributed and Authoring (DAV) server must be prevented
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228430

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal /v DisableDav /t REG_DWORD /d 1 /f
rem V-228431 - Level of calendar details that a user can publish must be restricted
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228431

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal /v PublishCalendarDetailsPolicy /t REG_DWORD /d 16384 /f
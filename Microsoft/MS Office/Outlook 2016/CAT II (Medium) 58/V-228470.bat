rem V-228470 - Internet calendar integration in Outlook must be disabled
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228470
rem This policy setting allows you to determine whether or not you want to include Internet Calendar integration in Outlook. The Internet Calendar feature in Outlook enables users to publish calendars online (using the webcal:// protocol) and subscribe to calendars that others have published. When users subscribe to an Internet calendar, Outlook queries the calendar at regular intervals and downloads any changes as they are posted. If you enable this policy setting, all Internet calendar functionality in Outlook is disabled. If you disable or do not configure this policy setting, Outlook allows users to subscribe to Internet calendars. 

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\webcal /v Disable /t REG_DWORD /d 1 /f
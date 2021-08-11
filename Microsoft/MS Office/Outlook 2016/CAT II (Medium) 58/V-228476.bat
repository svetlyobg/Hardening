rem V-228476 - Check e-mail addresses against addresses of certificates being used must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228476
rem This policy setting controls whether Outlook verifies the user's e-mail address with the address associated with the certificate used for signing. If you enable this policy setting, users can send messages signed with certificates that do not match their e-mail addresses. If you disable or do not configure this policy setting, Outlook verifies that the user's e-mail address matches the certificate being used for signing.

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v SupressNameChecks /t REG_DWORD /d 1 /f
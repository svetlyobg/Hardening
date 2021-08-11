rem V-228475 - Replies or forwards to signed/encrypted messages must be signed/encrypted
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228475
rem This policy setting controls whether replies and forwards to signed/encrypted mail should also be signed/encrypted. If you enable this policy setting, signing/encryption will be turned on when replying/forwarding a signed or encrypted message, even if the user is not configured for SMIME. If you disable or do not configure this policy setting, signing/encryption is not enforced. 

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v NoCheckOnSessionSecurity /t REG_DWORD /d 1 /f
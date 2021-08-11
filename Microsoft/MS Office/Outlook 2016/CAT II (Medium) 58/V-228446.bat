rem V-228446 - Object Model Prompt behavior for programmatic address books must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228446

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v PromptOOMAddressBookAccess /t REG_DWORD /d 0 /f
rem V-228447 - Object Model Prompt behavior for programmatic access of user address data must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228447

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v PromptOOMAddressInformationAccess /t REG_DWORD /d 0 /f
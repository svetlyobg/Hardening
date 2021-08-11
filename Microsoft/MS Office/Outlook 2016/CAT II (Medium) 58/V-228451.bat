rem V-228451 - Trusted add-ins behavior for email must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228451

reg delete HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v trustedaddins /f
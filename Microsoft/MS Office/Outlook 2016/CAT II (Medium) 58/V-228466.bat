rem V-228466 - RPC encryption between Outlook and Exchange server must be enforced
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228466

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\rpc /v EnableRPCEncryption /t REG_DWORD /d 1 /f
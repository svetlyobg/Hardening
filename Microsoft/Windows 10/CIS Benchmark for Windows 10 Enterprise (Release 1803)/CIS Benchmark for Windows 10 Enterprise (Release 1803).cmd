rem WAZUH

rem CIS Benchmark for Windows 10 Enterprise (Release 1803)

rem Check not applicable due to:

rem Key 'NoConnectedUser' not found for registry 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

rem Rationale
rem Organizations that want to effectively implement identity management policies and maintain firm control of what accounts are used to log onto their computers will probably in order to meet the requirements of compliance standards that apply to their information systems.

rem Remediation
rem To establish the recommended configuration via GP, set the following UI path to Users can't add or log on with Microsoft accounts: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Block Microsoft accounts.

rem Description
rem This policy setting prevents users from adding new Microsoft accounts on this computer. The recommended state for this setting is: Users can't add or log on with Microsoft accounts.

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoConnectedUser /t REG_DWORD /d 3 /f


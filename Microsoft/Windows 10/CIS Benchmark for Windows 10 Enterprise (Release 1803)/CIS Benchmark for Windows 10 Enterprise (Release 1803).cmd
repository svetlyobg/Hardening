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

rem TITLE
rem Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'

rem Rationale
rem Bluetooth technology has inherent security risks - especially prior to the v2.1 standard. Wireless Bluetooth traffic is not well encrypted (if at all), so in a high-security environment, it should not be permitted, in spite of the added inconvenience of not being able to use Bluetooth devices.

rem Remediation
rem To establish the recommended configuration via GP, set the following UI path to: Disabled: Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Bluetooth Audio Gateway Service Note: This service was first introduced in Windows 10 Release 1803. It appears to have replaced the older Bluetooth Handsfree Service (BthHFSrv), which was removed from Windows in that release (it is not simply a rename, but a different service).

rem Description
rem Service supporting the audio gateway role of the Bluetooth Handsfree Profile. The recommended state for this setting is: Disabled.

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService" /v Start /t REG_DWORD /d 4 /f

rem Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_DWORD /d 2 /f

rem Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Internet Connection Sharing (ICS) (SharedAccess) ' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManager"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Server (LanmanServer)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost"/v Start /t REG_DWORD /d 4 /f

rem Ensure 'Windows Error Reporting Service (WerSvc)' is set to 'Disabled'
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc"/v Start /t REG_DWORD /d 4 /f
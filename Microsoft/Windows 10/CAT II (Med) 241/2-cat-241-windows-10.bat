rem V-220709 - Alternate operating systems must not be permitted on the same system
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220709
rem manual check
rem Run "Advanced System Settings".
rem Select the "Advanced" tab.
rem Click the "Settings" button in the "Startup and Recovery" section.
rem If the drop-down list box "Default operating system:" shows any operating system other than Windows 10, this is a finding.

rem V-220830 - Enhanced anti-spoofing for facial recognition must be enabled on Window 10.
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220830
reg add "HKLM\Software\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
echo enabled "V-220830 - Enhanced anti-spoofing for facial recognition must be enabled on Window 10"

rem V-220836 - The Windows Defender SmartScreen for Explorer must be enabled.
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220836
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f

rem V-220837 - Explorer Data Execution Prevention must be enabled..
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220837
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f

rem V-220834 - Windows Telemetry must not be configured to Full.
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220834
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

rem V-220833 - If Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows Analytics.
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220833
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f

rem V-220701 - Windows 10 must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220701
rem DoD N/A

rem V-220702 - Windows 10 information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest.
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220702
rem manual check

rem Windows 10 systems must use a BitLocker PIN for pre-boot authentication.
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220703
rem manual check
rem reg add "HKLM\Software\Policies\Microsoft\FVE" /v UseTPMPIN /t REG_DWORD /d 1 /f
rem reg add "HKLM\Software\Policies\Microsoft\FVE" /v UseTPMKeyPIN /t REG_DWORD /d 1 /f
rem to enable bitlocker network unlock
rem reg add "HKLM\Software\Policies\Microsoft\FVE" /v UseTPMPIN /t REG_DWORD /d 2 /f
rem reg add "HKLM\Software\Policies\Microsoft\FVE" /v UseTPMKeyPIN /t REG_DWORD /d 2 /f

rem V-220704 - Windows 10 systems must use a BitLocker PIN with a minimum length of 6 digits for pre-boot authentication
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220704
reg add "HKLM\Software\Policies\Microsoft\FVE" /v MinimumPIN /t REG_DWORD /d 6 /f

rem V-220705 - The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220705
rem Execute the following command, substituting [c:\temp\file.xml] with a location and file name appropriate for the system:
rem Get-AppLockerPolicy -Effective -XML > c:\temp\file.xml

rem V-220933 - Remote calls to the Security Account Manager (SAM) must be restricted to Administrators
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220933
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f

rem V-220931 - The system must be configured to prevent anonymous users from having the same rights as the Everyone group
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220931
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d O /f

rem V-220936 - Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220936
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f

rem V-220935 - PKU2U authentication using online identities must be prevented
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220935
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u" /v AllowOnlineID /t REG_DWORD /d O /f

rem V-220934 - NTLM must be prevented from falling back to a Null session
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220934
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d O /f

rem V-220939 - The system must be configured to the required LDAP client signing level
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220939
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f

rem V-220742 - The password history must be configured to 24 passwords remembered
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220742
rem manual check

rem V-220779 - The Application event log size must be configured to 32768 KB or greater
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220779
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" /v MaxSize /t REG_DWORD /d 220779 /f

rem V-220778 - The system must be configured to audit System - System Integrity successes
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220778
rem manual check
rem AuditPol /get /category:*

rem V-220748 - The system must be configured to audit Account Logon - Credential Validation failures
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220748
rem manual check
rem AuditPol /get /category:*

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220775
rem V-220775 - The system must be configured to audit System - Security State Change successes
rem manual check
rem AuditPol /get /category:*

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220774
rem V-220774 - The system must be configured to audit System - Other System Events failures
rem manual check
rem AuditPol /get /category:*

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220777
rem V-220777 - The system must be configured to audit System - System Integrity failures
rem manual check
rem AuditPol /get /category:*

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220776
rem V-220776 - The system must be configured to audit System - Security System Extension successes
rem manual check
rem AuditPol /get /category:*

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220771
rem V-220771 - The system must be configured to audit Privilege Use - Sensitive Privilege Use successes
rem manual check
rem AuditPol /get /category:*

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220773
rem V-220773 - The system must be configured to audit System - Other System Events successes
rem manual check
rem AuditPol /get /category:*

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220772
rem V-220772 - The system must be configured to audit System - IPSec Driver failures
rem manual check
rem AuditPol /get /category:*

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220824
rem V-220824 - Unauthenticated RPC clients must be restricted from connecting to the RPC server
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220719
rem V-220719 - Simple Network Management Protocol (SNMP) must not be installed on the system
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220821
rem V-220821 - Users must be prompted for a password on resume from sleep (on battery)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220820
rem V-220820 - Local users on domain-joined computers must not be enumerated
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnumerateLocalUsers /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220822
rem V-220822 - The user must be prompted for a password on resume from sleep (plugged in)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220713
rem V-220713 - Only accounts responsible for the backup operations must be members of the Backup Operators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220710
rem V-220710 - Non system-created file shares on a system must limit access to groups that require it
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220714
rem V-220714 - Only authorized user accounts must be allowed to create or run virtual machines on Windows 10 systems
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220906
rem V-220906 - The US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems
rem manual check
rem DoD N/A
rem PowerShell -> Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220907
rem V-220907 - Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220904
rem V-220904 - The External Root CA certificates must be installed in the Trusted Root Store on unclassified systems
rem manual check
rem PowerShell -> Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*ECA*" | FL Subject, Thumbprint, NotAfter

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220905
rem V-220905 - The DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems
rem manual check
rem DoD N/A
rem PowerShell -> Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220902
rem V-220902 - Windows 10 Kernel (Direct Memory Access) DMA Protection must be enabled
reg add "HKLM\Software\Policies\Microsoft\Windows\Kernel DMA Protection" /v DeviceEnumerationPolicy /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220903
rem V-220903 - The DoD Root CA certificates must be installed in the Trusted Root Store
rem manual check
rem DoD N/A
rem PowerShell -> Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220900
rem V-220900 - Exploit Protection mitigations in Windows 10 must be configured for wmplayer.exe
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name wmplayer.exe
rem Get-ProcessMitigation can be run without the -Name parameter to get a list of all application mitigations configured

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220901
rem V-220901 - Exploit Protection mitigations in Windows 10 must be configured for wordpad.exe
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name wordpad.exe
rem Get-ProcessMitigation can be run without the -Name parameter to get a list of all application mitigations configured

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220908
rem 220908 - The built-in administrator account must be disabled
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220909
rem 220909 - The built-in guest account must be disabled
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220819
rem V-220819 - The network selection user interface (UI) must not be displayed on the logon screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220982
rem 220982 - The Restore files and directories user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220983
rem 220983 - The Take ownership of files or other objects user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220980
rem 220980 - The Perform volume maintenance tasks user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220981
rem 220981 - The Profile single process user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220780
rem V-220780 - The Security event log size must be configured to 1024000 KB or greater
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" /v MaxSize /t REG_DWORD /d 1024000 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220781
rem V-220781 - The System event log size must be configured to 32768 KB or greater
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" /v MaxSize /t REG_DWORD /d 32768 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220782
rem 220782 - Windows 10 permissions for the Application event log must prevent access by non-privileged accounts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220783
rem 220783 - Windows 10 permissions for the Security event log must prevent access by non-privileged accounts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220784
rem 220784 - Windows 10 permissions for the System event log must prevent access by non-privileged accounts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220785
rem 220785 - Windows 10 must be configured to audit Other Policy Change Events Successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220786
rem 220786 - Windows 10 must be configured to audit Other Policy Change Events Failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220787
rem 220787 - Windows 10 must be configured to audit other Logon/Logoff Events Successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220788
rem 220788 - Windows 10 must be configured to audit other Logon/Logoff Events Failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220789
rem 220789 - Windows 10 must be configured to audit Detailed File Share Failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220839
rem V-220839 - File Explorer shell protocol must run in protected mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220919
rem V-220919 - The system must be configured to require a strong session key
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220728
rem 220728 - The Windows PowerShell 2.0 feature must be disabled on the system
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220729
rem 220729 - The Server Message Block (SMB) v1 protocol must be disabled on the system
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220724
rem 220724 - A host-based firewall must be installed and enabled on the system
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220725
rem 220725 - Inbound exceptions to the firewall on Windows 10 domain workstations must only allow authorized remote management hosts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220915
rem 220915 - Outgoing secure channel traffic must be encrypted when possible
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220914
rem 220914 - Outgoing secure channel traffic must be encrypted or signed
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220720
rem 220720 - Simple TCP/IP Services must not be installed on the system
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220721
rem 220721 - The Telnet Client must not be installed on the system
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220850
rem 220850 - Remote Desktop Services must always prompt a client for passwords upon connection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v RequireSignOfPromptForPasswordrSeal /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220851
rem 220851 - The Remote Desktop Session Host must require secure RPC communications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220852
rem 220852 - Remote Desktop Services must be configured with the client connection encryption set to the required level
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220853
rem 220853 - Attachments must be prevented from being downloaded from RSS feeds
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v DisableEnclosureDownload /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220854
rem 220854 - Basic authentication for RSS feeds over HTTP must not be used
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v AllowBasicAuthInClear /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220855
rem 220855 - Indexing of encrypted files must be turned off
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220856
rem 220856 - Users must be prevented from changing installation options
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v EnableUserControl /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220858
rem 220858 - Users must be notified if a web-based program attempts to install software
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v EnableUserConSafeForScriptingtrol /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220859
rem 220859 - Automatically signing in the last interactive user after a system-initiated restart must be disabled
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220755
rem 220755 - The system must be configured to audit Logon/Logoff - Account Lockout failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220734
rem 220734 - Bluetooth must be turned off unless approved by the organization
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220866
rem 220866 - The Windows Remote Management (WinRM) service must not allow unencrypted traffic
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220793
rem 220793 - Windows 10 must cover or disable the built-in or attached camera when not in use
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d Deny /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220792
rem 220792 - Camera access from the lock screen must be disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220791
rem 220791 - Windows 10 must be configured to audit MPSSVC Rule-Level Policy Change Failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220790
rem 220790 - Windows 10 must be configured to audit MPSSVC Rule-Level Policy Change Successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220796
rem 220796 - The system must be configured to prevent IP source routing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220795
rem 220795 - IPv6 source routing must be configured to highest protection
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIpSourceRouting /t REG_DWORD /d 2 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220794
rem 220794 - The display of slide shows on the lock screen must be disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenSlideshow /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220799
rem 220799 - Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220731
rem 220731 - The Server Message Block (SMB) v1 protocol must be disabled on the SMB client
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220730
rem 220730 - The Server Message Block (SMB) v1 protocol must be disabled on the SMB server
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220733
rem 220733 - Orphaned security identifiers (SIDs) must be removed from user rights on Windows 10
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220732
rem 220732 - The Secondary Logon service must be disabled on Windows 10
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220735
rem 220735 - Bluetooth must be turned off when not in use
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220969
rem 220969 - The Deny log on as a batch job user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220736
rem 220736 - The system must notify the user when a Bluetooth device attempts to connect
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220739
rem 220739 - Windows 10 account lockout duration must be configured to 15 minutes or greater
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220738
rem 220738 - Windows 10 non-persistent VM sessions should not exceed 24 hours
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220966
rem 220966 - The Create symbolic links user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220960
rem 220960 - The Back up files and directories user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220961
rem 220961 - The Change the system time user right must only be assigned to Administrators and Local Service and NT SERVICE\autotimesvc
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220962
rem 220962 - The Create a pagefile user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220843
rem 220843 - The password manager function in the Edge browser must be disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220842
rem 220842 - Windows 10 must be configured to prevent certificate error overrides in Microsoft Edge
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings" /v PreventCertErrorOverrides /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220841
rem 220841 - Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in Microsoft Edge
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v PreventOverrideAppRepUnknown /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220840
rem 220840 - Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in Microsoft Edge
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v PreventOverride /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220847
rem 220847 - Windows 10 must be configured to require a minimum pin length of six characters or greater
reg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" /v MinimumPINLength /t REG_DWORD /d 6 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220846
rem 220846 - The use of a hardware security device with Windows Hello for Business must be enabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v RequireSecurityDevice /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220845
rem 220845 - Windows 10 must be configured to disable Windows Game Recording and Broadcasting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220844
rem 220844 - The Windows Defender SmartScreen filter for Microsoft Edge must be enabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220849
rem 220849 - Local drives must be prevented from sharing with Remote Desktop Session Hosts
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220848
rem 220848 - Passwords must not be saved in the Remote Desktop Client
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v DisablePasswordSaving /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220926
rem 220926 - Unencrypted passwords must not be sent to third-party SMB Servers
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220832
rem 220832 - Administrator accounts must not be enumerated during elevation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v EnumerateAdministrators /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220744
rem 220744 - The minimum password age must be configured to at least 1 day
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220745
rem 220745 - Passwords must, at a minimum, be 14 characters
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220746
rem 220746 - The built-in Microsoft password complexity filter must be enabled
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220740
rem 220740 - The number of allowed bad logon attempts must be configured to 3 or less
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220741
rem 220741 - The period of time before the bad logon counter is reset must be configured to 15 minutes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220979
rem 220979 - The Modify firmware environment values user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220978
rem 220978 - The Manage auditing and security log user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220977
rem 220977 - The Lock pages in memory user right must not be assigned to any groups or accounts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220976
rem 220976 - The Load and unload device drivers user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220975
rem 220975 - The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220974
rem 220974 - The Force shutdown from a remote system user right must only be assigned to the Administrators group
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220973
rem 220973 - The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220749
rem 220749 - The system must be configured to audit Account Logon - Credential Validation successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220971
rem 220971 - The Deny log on locally user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220970
rem 220970 - The Deny log on as a service user right on Windows 10 domain-joined workstations must be configured to prevent access from highly privileged domain accounts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220876
rem 220876 - Windows 10 Exploit Protection system-level mitigation, Validate exception chains (SEHOP), must be on
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220877
rem 220877 - Windows 10 Exploit Protection system-level mitigation, Validate heap integrity, must be on
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220874
rem 220874 - Windows 10 Exploit Protection system-level mitigation, Randomize memory allocations (Bottom-Up ASLR), must be on
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220875
rem 220875 - Windows 10 Exploit Protection system-level mitigation, Control flow guard (CFG), must be on
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220873
rem 220873 - Windows 10 Exploit Protection system-level mitigation, Data Execution Prevention (DEP), must be on
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220870
rem 220870 - The convenience PIN for Windows 10 must be disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v AllowDomainPINLogon /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220871
rem 220871 - Windows Ink Workspace must be configured to disallow access above the lock
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220818
rem 220818 - Systems must at least attempt device authentication using certificates
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v DevicePKInitEnabled /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220878
rem 220878 - Exploit Protection mitigations in Windows 10 must be configured for Acrobat.exe
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220879
rem 220879 - Exploit Protection mitigations in Windows 10 must be configured for AcroRd32.exe
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220800
rem 220800 - WDigest Authentication must be disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" /v UseLogonCredential /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220911
rem 220911 - The built-in administrator account must be renamed
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220910
rem 220910 - Local accounts with blank passwords must be restricted to prevent access from the network
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220810
rem 220810 - Windows 10 must be configured to enable Remote host allows delegation of non-exportable credentials
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220913
rem 220913 - Audit policy using subcategories must be enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220757
rem 220757 - The system must be configured to audit Logon/Logoff - Logoff successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220756
rem 220756 - The system must be configured to audit Logon/Logoff - Group Membership successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220940
rem 220940 - The system must be configured to meet the minimum session security requirement for NTLM SSP based clients
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220941
rem 220941 - The system must be configured to meet the minimum session security requirement for NTLM SSP based servers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220753
rem 220753 - The system must be configured to audit Detailed Tracking - PNP Activity successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220752
rem 220752 - The system must be configured to audit Account Management - User Account Management successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220751
rem 220751 - The system must be configured to audit Account Management - User Account Management failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220750
rem 220750 - The system must be configured to audit Account Management - Security Group Management successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220861
rem 220861 - The Windows Explorer Preview pane must be disabled for Windows 10
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPreviewPane /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPreviewPane /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220722
rem 220722 - The TFTP Client must not be installed on the system
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220863
rem 220863 - The Windows Remote Management (WinRM) client must not allow unencrypted traffic
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220759
rem 220759 - The system must be configured to audit Logon/Logoff - Logon successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220723
rem 220723 - Software certificate installation files must be removed from Windows 10
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220968
rem 220968 - The Deny access to this computer from the network user right on workstations must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220883
rem 220883 - Exploit Protection mitigations in Windows 10 must be configured for FLTLDR.EXE
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220916
rem 220916 - Outgoing secure channel traffic must be signed when possible
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220964
rem 220964 - The Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220770
rem 220770 - The system must be configured to audit Privilege Use - Sensitive Privilege Use failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220955
rem 220955 - Zone information must be preserved when saving attachments
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220957
rem 220957 - The Access this computer from the network user right must only be assigned to the Administrators and Remote Desktop Users groups
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220956
rem 220956 - The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220951
rem 220951 - User Account Control must virtualize file and registry write failures to per-user locations
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220912
rem 220912 - The built-in guest account must be renamed
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220952
rem 220952 - Passwords for enabled local Administrator accounts must be changed at least every 60 days
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220814
rem 220814 - Group Policy objects must be reprocessed even if they have not changed
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220815
rem 220815 - Downloading print driver packages over HTTP must be prevented
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220816
rem 220816 - Web publishing and online ordering wizards must be prevented from downloading a list of providers
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWebServices /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220817
rem 220817 - Printing over HTTP must be prevented
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220959
rem 220959 - The Allow log on locally user right must only be assigned to the Administrators and Users groups
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220813
rem 220813 - Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f
rem Possible values for this setting are:
rem UEFI Secure Boot should be enabled
rem 8 - Good only - very restrictive, computer might not boot
rem 1 - Good and unknown
rem 3 - Good, unknown and bad but critical
rem 7 - All (which includes "Bad" and would be a finding)

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220868
rem 220868 - The Windows Remote Management (WinRM) client must not use Digest authentication
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220754
rem 220754 - The system must be configured to audit Detailed Tracking - Process Creation successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220946
rem 220946 - Windows 10 must use multifactor authentication for local and network access to privileged and non-privileged accounts
rem reg query "HKLM\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers"
rem reg query "HKLM\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards"
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220947
rem 220947 - User Account Control must automatically deny elevation requests for standard users
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220743
rem 220743 - The maximum password age must be configured to 60 days or less
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220895
rem 220895 - Exploit Protection mitigations in Windows 10 must be configured for POWERPNT.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name POWERPNT.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220896
rem 220896 - Exploit Protection mitigations in Windows 10 must be configured for PPTVIEW.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name PPTVIEW.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220897
rem 220897 - Exploit Protection mitigations in Windows 10 must be configured for VISIO.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name VISIO.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220890
rem 220890 - Exploit Protection mitigations in Windows 10 must be configured for MSPUB.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name MSPUB.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220890
rem 220890 - Exploit Protection mitigations in Windows 10 must be configured for MSPUB.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name MSPUB.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220944
rem 220944 - User Account Control approval mode for the built-in Administrator must be enabled
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220893
rem 220893 - Exploit Protection mitigations in Windows 10 must be configured for OUTLOOK.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name MSOUTLOOKPUB.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220965
rem 220965 - The Create permanent shared objects user right must not be assigned to any groups or accounts
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220945
rem 220945 - User Account Control must, at minimum, prompt administrators for consent on the secure desktop
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220898
rem 220898 - Exploit Protection mitigations in Windows 10 must be configured for VPREVIEW.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name VPREVIEW.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220899
rem 220899 - Exploit Protection mitigations in Windows 10 must be configured for WINWORD.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name WINWORD.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220697
rem 220697 - Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220972
rem 220972 - The Deny log on through Remote Desktop Services user right on Windows 10 workstations must at a minimum be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220860
rem 220860 - PowerShell script block logging must be enabled on Windows 10
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220948
rem 220948 - User Account Control must be configured to detect application installations and prompt for elevation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220698
rem 220698 - Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use
tpm.msc

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220699
rem 220699 - Windows 10 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220942
rem 220942 - The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" /v Enabled /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220894
rem 220894 - Exploit Protection mitigations in Windows 10 must be configured for plugin-container.exe
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name plugin-container.EXE

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220949
rem 220949 - User Account Control must only elevate UIAccess applications that are installed in secure locations
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220809
rem 220809 - Command line data must be included in process creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220808
rem 220808 - Wi-Fi Sense must be disabled
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220807
rem 220807 - Connections to non-domain networks when connected to a domain authenticated network must be blocked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fBlockNonDomain /t REG_DWORD /d 1 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220806
rem 220806 - Simultaneous connections to the Internet or a Windows domain must be limited
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220805
rem 220805 - Windows 10 must be configured to prioritize ECC Curves with longer key lengths first
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v fMinimizeCoEccCurvesnnections /t REG_MULTI_SZ /d "NistP384 NistP256" /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220804
rem 220804 - Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v \\*\NETLOGON /t REG_SZ /d "RequireMutualAuthentication=1, RequireIntegrity=1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v \\*\SYSVOL /t REG_SZ /d "RequireMutualAuthentication=1, RequireIntegrity=1" /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220803
rem 220803 - Internet connection sharing must be disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220802
rem 220802 - Insecure logons to an SMB server must be disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220801
rem 220801 - Run as different user must be removed from context menus
reg add "HKLM\SOFTWARE\Classes\batfile\shell\runasuser" /v SuppressionPolicy /t REG_DWORD /d 4096 /f
reg add "HKLM\SOFTWARE\Classes\batfile\cmdfile\runasuser" /v SuppressionPolicy /t REG_DWORD /d 4096 /f
reg add "HKLM\SOFTWARE\Classes\batfile\exefile\runasuser" /v SuppressionPolicy /t REG_DWORD /d 4096 /f
reg add "HKLM\SOFTWARE\Classes\batfile\mscfile\runasuser" /v SuppressionPolicy /t REG_DWORD /d 4096 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220716
rem 220716 - Accounts must be configured to require password expiration
rem manual check

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220920
rem 220920 - The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220921
rem 220921 - The required legal notice must be configured to display before console logon
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LegalNoticeText /t REG_SZ /d "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220924
rem 220924 - The Smart Card removal option must be configured to Force Logoff or Lock Workstation
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_SZ /d 1 /f
rem reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_SZ /d 2 /f is for Force Logoff

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220925
rem 220925 - The Windows SMB client must be configured to always perform SMB packet signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220869
rem 220869 - Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220927
rem 220927 - The Windows SMB server must be configured to always perform SMB packet signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220758
rem 220758 - The system must be configured to audit Logon/Logoff - Logon failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220891
rem 220891 - Exploit Protection mitigations in Windows 10 must be configured for OIS.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name OIS.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220887
rem 220887 - Exploit Protection mitigations in Windows 10 must be configured for java.exe, javaw.exe, and javaws.exe
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name java.EXE
rem PowerShell -> Get-ProcessMitigation -Name javaw.EXE
rem PowerShell -> Get-ProcessMitigation -Name javaws.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220886
rem 220886 - Exploit Protection mitigations in Windows 10 must be configured for INFOPATH.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name INFOPATH.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220885
rem 220885 - Exploit Protection mitigations in Windows 10 must be configured for iexplore.exe
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name iexplore.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220884
rem 220884 - Exploit Protection mitigations in Windows 10 must be configured for GROOVE.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name GROOVE.EXE

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220867
rem 220867 - The Windows Remote Management (WinRM) service must not store RunAs credentials
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v DisableRunAs /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220882
rem 220882 - Exploit Protection mitigations in Windows 10 must be configured for firefox.exe
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name firefox.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220881
rem 220881 - Exploit Protection mitigations in Windows 10 must be configured for EXCEL.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name EXCEL.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220880
rem 220880 - Exploit Protection mitigations in Windows 10 must be configured for chrome.exe
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name chrome.EXE

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220950
rem 220950 - User Account Control must run all administrators in Admin Approval Mode, enabling UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f

rem rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-230220
rem 230220 - PowerShell Transcription must be enabled on Windows 10
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220889
rem 220889 - Exploit Protection mitigations in Windows 10 must be configured for MSACCESS.EXE
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name MSACCESS.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220888
rem 220888 - Exploit Protection mitigations in Windows 10 must be configured for lync.exe
rem manual check
rem PowerShell -> Get-ProcessMitigation -Name lync.EXE

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220768
rem 220768 - The system must be configured to audit Policy Change - Authentication Policy Change successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220769
rem 220769 - The system must be configured to audit Policy Change - Authorization Policy Change successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220762
rem 220762 - The system must be configured to audit Policy Change - Authorization Policy Change successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220763
rem 220763 - Windows 10 must be configured to audit Object Access - Other Object Access Events successes
rem manual check
rem PowerShell -> AuditPol /get /category:*

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220760
rem 220760 - The system must be configured to audit Logon/Logoff - Special Logon successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220761
rem 220761 - Windows 10 must be configured to audit Object Access - File Share failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220766
rem 220766 - The system must be configured to audit Object Access - Removable Storage successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220767
rem 220767 - The system must be configured to audit Policy Change - Audit Policy Change successes
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220764
rem 220764 - Windows 10 must be configured to audit Object Access - Other Object Access Events failures
rem manual check

rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220765
rem 220765 - The system must be configured to audit Object Access - Removable Storage failures
rem manual check

rem https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-3453
rem 3453 - Remote Desktop Services must always prompt a client for passwords upon connection
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword /t REG_DWORD /d 1 /f



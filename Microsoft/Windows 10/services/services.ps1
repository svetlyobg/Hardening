Write-host "Provides User Account Control validation for the installation of ActiveX controls from the Internet and enables management of ActiveX control"
Set-Service -Name AxInstSV -StartupType Disabled -Status Stopped -Verbose

Write-host "Provides User Account Control validation for the installation of ActiveX controls from the Internet and enables management of ActiveX control"
Set-Service -Name AJRouter -StartupType Manual -Status Stopped -Verbose #Running

Write-host "Gets apps ready for use the first time a user signs in to this PC and when adding new apps"
Set-Service -Name AppReadiness -StartupType Manual -Status Stopped -Verbose #Running

Write-host "Determines and verifies the identity of an application. Disabling this service will prevent AppLocker from being enforced"
Set-Service -Name AppIDSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-host "Facilitates the running of interactive applications with additional administrative privileges"
Set-Service -Name Appinfo -StartupType Manual -Status Stopped -Verbose #Running

Write-host "Provides support for 3rd party protocol plug-ins for Internet Connection Sharing"
Set-Service -Name ALG -StartupType Disabled -Status Stopped -Verbose

Write-host "Processes installation, removal, & enumeration requests for software deployed through Group Policy"
Set-Service -Name AppMgmt -StartupType Manual -Status Stopped -Verbose #Running

Write-host "Provides infrastructure support for deploying Store applications"
Set-Service -Name AppXSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "AssignedAccessManager Local Server"
Set-Service -Name AssignedAccessManagerSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Automatically sets the system time zone"
Set-Service -Name tzautoupdate -StartupType Disabled -Status Stopped -Verbose

Write-Host "Transfers files in the background using idle network bandwidth"
Set-Service -Name BITS -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Windows infrastructure service that controls which background tasks can run on the system"
Set-Service -Name BrokerInfrastructure -StartupType Auto -Status Running -Verbose

Write-Host "The Base Filtering Engine (BFE) is a service that manages firewall and Internet Protocol security (IPsec) policies and implements user mode..."
Set-Service -Name BFE -StartupType Auto -Status Running -Verbose

Write-Host "Allows BitLocker to prompt users for actions related to drives when accessed and supports unlocking of BL-protected drives automatically..."
Set-Service -Name BDESVC -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "The WBENGINE service is used by Windows Backup to perform backup and recovery operations"
Set-Service -Name wbengine -StartupType Disabled -Status Stopped -Verbose

Write-Host "Enables wireless Bluetooth headsets to run on this computer"
Set-Service -Name BthHFSrv -StartupType Disabled -Status Stopped -Verbose

Write-Host "The Bluetooth service supports discovery and association of remote Bluetooth devices"
Set-Service -Name bthserv -StartupType Disabled -Status Stopped -Verbose

Write-Host "This service caches network content from peers on the local subnet"
Set-Service -Name PeerDistSvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "Provides facilities for managing UWP apps access to app capabilities as well as checking an app�s access to specific app capabilities"
Set-Service -Name camsvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "This user service is used for Connected Devices Platform scenarios"
Set-Service -Name CDPUserSvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "Copies user certificates and root certificates from smart cards into the current user�s certificate store, detects when a smart card is inserted"
Set-Service -Name CertPropSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Provides infrastructure support for the Microsoft Store"
Set-Service -Name ClipSVC -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "The CNG key isolation service is hosted in the LSA process"
Set-Service -Name KeyIso -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Supports System Event Notification Service, provides automatic distribution of events to subscribing Component Object Model (COM)"
Set-Service -Name EventSystem -StartupType Auto -Status Running -Verbose

Write-Host "Manages the configuration and tracking of Component Object Model (COM)+-based components"
Set-Service -Name COMSysApp -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "This service is used for Connected Devices and Universal Glass scenarios"
Set-Service -Name CDPSvc -StartupType Autp -Status Running -Verbose #Stopped

Write-Host "The Connected User Experiences and Telemetry service enables features that support in-application and connected user experiences"
Set-Service -Name DiagTrack -StartupType Auto -Status Running -Verbose

Write-Host "Indexes contact data for fast contact searching. If you stop or disable this service, contacts might be missing from your search results"
Set-Service -Name PimIndexMaintenanceSvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "Manages communication between system components"
Set-Service -Name CoreMessagingRegistrar -StartupType Auto -Status Running -Verbose

Write-Host "Provides secure storage and retrieval of credentials to users, applications and security service packages"
Set-Service -Name VaultSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Provides 3 management services: Catalog Database Service, confirms the signatures of Windows files and allows new programs to be installed"
Set-Service -Name CryptSvc -StartupType Auto -Status Running -Verbose

Write-Host "Provides data brokering between applications"
Set-Service -Name DsSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Network data usage, data limit, restrict background data, metered networks"
Set-Service -Name DusmSvc -StartupType Auto -Status Running -Verbose

Write-Host "The DCOMLAUNCH service launches COM and DCOM servers in response to object activation requests"
Set-Service -Name DcomLaunch -StartupType Auto -Status Running -Verbose

Write-Host "Performs content delivery optimization tasks"
Set-Service -Name DoSvc -StartupType Auto -Status Stopped -Verbose #Running

Write-Host "Enables pairing between the system and wired or wireless devices"
Set-Service -Name DeviceAssociationService -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Enables a computer to recognize and adapt to hardware changes with little or no user input"
Set-Service -Name DeviceInstall -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Performs Device Enrollment Activities for Device Management"
Set-Service -Name DmEnrollmentSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Enables the detection, download and installation of device-related software. If this service is disabled, devices may be configured with outdated"
Set-Service -Name DsmSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Device Discovery and Connecting"
Set-Service -Name DevicesFlowUserSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Enables apps to discover devices with a backgroud task"
Set-Service -Name DevQueryBroker -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Registers and updates IP addresses and DNS records for this computer"
Set-Service -Name Dhcp -StartupType Auto -Status Running -Verbose

Write-Host "Executes diagnostic actions for troubleshooting support"
Set-Service -Name diagsvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "The Diagnostic Policy Service enables problem detection, troubleshooting and resolution for Windows components"
Set-Service -Name DPS -StartupType Auto -Status Running -Verbose

Write-Host "The Diagnostic Service Host is used by the Diagnostic Policy Service to host diagnostics that need to run in a Local Service context"
Set-Service -Name WdiServiceHost -StartupType Disabled -Status Stopped -Verbose

Write-Host "The Diagnostic System Host is used by the Diagnostic Policy Service to host diagnostics that need to run in a Local System context"
Set-Service -Name WdiSystemHost -StartupType Disabled -Status Stopped -Verbose

Write-Host "Maintains links between NTFS files within a computer or across computers in a network"
Set-Service -Name TrkWks -StartupType Auto -Status Running -Verbose

Write-Host "Coordinates transactions that span multiple resource managers, such as databases, message queues, and file systems"
Set-Service -Name MSDTC -StartupType Auto -Status Running -Verbose

Write-Host "WAP Push Message Routing Service"
Set-Service -Name dmwappushservice -StartupType Disabled -Status Stopped -Verbose

Write-Host "The DNS Client service (dnscache) caches Domain Name System (DNS) names and registers the full computer name for this computer"
Set-Service -Name Dnscache -StartupType Auto -Status Running -Verbose

Write-Host "Windows service for application access to downloaded maps. This service is started on-demand by application accessing downloaded maps"
Set-Service -Name MapsBroker -StartupType Disabled -Status Stopped -Verbose

Write-Host "The Embedded Mode service enables scenarios related to Background Applications"
Set-Service -Name embeddedmode -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Provides the core file encryption technology used to store encrypted files on NTFS file system volumes"
Set-Service -Name EFS -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Enables enterprise application management"
Set-Service -Name EntAppSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Enables enterprise application management"
Set-Service -Name EntAppSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Provides network authentication in such scenarios as 802.1x wired and wireless, VPN, and Network Access Protection (NAP)"
Set-Service -Name EapHost -StartupType Disabled -Status Stopped -Verbose

Write-Host "The Fax service, a Telephony API (TAPI)-compliant service, provides fax capabilities from users’ computers"
Set-Service -Name Fax -StartupType Disabled -Status Stopped -Verbose

Write-Host "Protects user files from accidental loss by copying them to a backup location"
Set-Service -Name fhsvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "The FDPHOST service hosts the Function Discovery (FD) network discovery providers"
Set-Service -Name fdPHost -StartupType Disabled -Status Stopped -Verbose

Write-Host "Publishes this computer and resources attached to this computer so they can be discovered over the network"
Set-Service -Name FDResPub -StartupType Disabled -Status Stopped -Verbose

Write-Host "This service monitors the current location of the system and manages geofences (a geographical location with associated events)"
Set-Service -Name lfsvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "Graphics performance monitor service"
Set-Service -Name GraphicsPerfSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "The service is responsible for applying settings configured by administrators for the computer and users through the Group Policy component"
Set-Service -Name gpsvc -StartupType Auto -Status Running -Verbose

Write-Host "Makes local computer changes associated with configuration and maintenance of the homegroup-joined computer"
Set-Service -Name HomeGroupListener -StartupType Disabled -Status Stopped -Verbose

Write-Host "Performs networking tasks associated with configuration and maintenance of homegroups"
Set-Service -Name HomeGroupProvider -StartupType Disabled -Status Stopped -Verbose

Write-Host "Activates and maintains the use of hot buttons on keyboards, remote controls, and other multimedia devices"
Set-Service -Name hidserv -StartupType Disabled -Status Stopped -Verbose

Write-Host "Graphics performance monitor service"
Set-Service -Name HvHost -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Provides an interface for the Hyper-V hypervisor to provide per-partition performance counters to the host operating system"
Set-Service -Name GraphicsPerfSvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Provides a mechanism to exchange data between the virtual machine and the operating system running on the physical computer"
Set-Service -Name vmickvpexchange -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Provides an interface for the Hyper-V host to interact with specific services running inside the virtual machine"
Set-Service -Name vmicguestinterface -StartupType Manual -Status Running -Verbose #Stopped

Write-Host "Provides a mechanism to shut down the operating system of this virtual machine from the management interfaces on the physical computer"
Set-Service -Name vmicshutdown -StartupType Manual -Status Running -Verbose #Stopped

Write-Host "Monitors the state of this virtual machine by reporting a heartbeat at regular intervals"
Set-Service -Name vmicshutdown -StartupType Manual -Status Running -Verbose #Stopped

Write-Host "Provides a mechanism to manage virtual machine with PowerShell via VM session without a virtual network"
Set-Service -Name vmicvmsession -StartupType Manual -Status Running -Verbose #Stopped

Write-Host "Provides a platform for communication between the virtual machine and the operating system running on the physical computer"
Set-Service -Name vmicrdv -StartupType Manual -Status Running -Verbose #Stopped

Write-Host "Synchronizes the system time of this virtual machine with the system time of the physical computer"
Set-Service -Name vmictimesync -StartupType Manual -Status Running -Verbose #Stopped

Write-Host "Coordinates the communications that are required to use Volume Shadow Copy Service to back up applications and data on this virtual machine"
Set-Service -Name vmicvss -StartupType Manual -Status Running -Verbose #Stopped

Write-Host "The IISAdmin service hosts the IIS 6.0 configuration compatibility component (metabase) required by IIS 6.0 administrative scripts, SMTP & FTP"
Set-Service -Name IISADMIN -StartupType Disabled -Status Stopped -Verbose

Write-Host "The IKEEXT service hosts the Internet Key Exchange (IKE) and Authenticated Internet Protocol (AuthIP) keying modules"
Set-Service -Name IKEEXT -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Detects other Infrared devices that are in range and launches the file transfer application"
Set-Service -Name irmon -StartupType Disabled -Status Stopped -Verbose

Write-Host "Enables user notification of user input for interactive services, which enables access to dialogs created by interactive services when they appear"
Set-Service -Name UI0Detect -StartupType Disabled -Status Stopped -Verbose

Write-Host "Provides network address translation, addressing, name resolution and/or intrusion prevention services for a home or small office network"
Set-Service -Name SharedAccess -StartupType Disabled -Status Stopped -Verbose

Write-Host "Provides tunnel connectivity using IPv6 transition technologies (6to4, ISATAP, Port Proxy, and Teredo), and IP-HTTPS"
Set-Service -Name iphlpsvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "Configures and enables translation from v4 to v6 and vice versa"
Set-Service -Name IpxlatCfgSvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "The IKEEXT service hosts the Internet Key Exchange (IKE) and Authenticated Internet Protocol (AuthIP) keying modules"
Set-Service -Name PolicyAgent -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "The IKEEXT service hosts the Internet Key Exchange (IKE) and Authenticated Internet Protocol (AuthIP) keying modules"
Set-Service -Name KtmRm -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Creates a Network Map, consisting of PC and device topology (connectivity) information, and metadata describing each PC and device"
Set-Service -Name lltdsvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "This service provides profile management for subscriber identity modules"
Set-Service -Name wlpasvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Core Windows Service that manages local user sessions. Stopping or disabling this service will result in system instability"
Set-Service -Name LSM -StartupType Auto -Status Running -Verbose

Write-Host "The LXSS Manager service supports running native ELF binaries"
Set-Service -Name LxssManager -StartupType Disabled -Status Stopped -Verbose

Write-Host "Service supporting text messaging and related functionality"
Set-Service -Name MessagingService -StartupType Disabled -Status Stopped -Verbose

Write-Host "Diagnostics Hub Standard Collector Service. When running, this service collects real time ETW events and processes them"
Set-Service -Name diagnosticshub.standardcollector.service -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "Manages App-V users and virtual applications"
Set-Service -Name AppVClient -StartupType Disabled -Status Stopped -Verbose

Write-Host "Enables user sign-in through Microsoft account identity services"
Set-Service -Name wlidsvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "Enables the server to be a File Transfer Protocol (FTP) server"
Set-Service -Name FTPSVC -StartupType Disabled -Status Stopped -Verbose

Write-Host "Manages Internet SCSI (iSCSI) sessions from this computer to remote iSCSI target devices"
Set-Service -Name MSiSCSI -StartupType Disabled -Status Stopped -Verbose

Write-Host "Provides process isolation for cryptographic keys used to authenticate to a user's associated identity providers"
Set-Service -Name NgcSvc -StartupType Disabled -Status Stopped -Verbose









Write-host "Coordinates transactions that span multiple resource managers, such as databases, message queues, and file systems"
Set-Service -Name MSDTC -StartupType Auto -Status Running -Verbose

Write-Host "WAP Push Message Routing Service"
Set-Service -Name dmwappushservice -StartupType Disabled -Status Stopped -Verbose

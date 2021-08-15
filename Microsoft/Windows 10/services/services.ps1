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

Write-Host "Provides facilities for managing UWP apps access to app capabilities as well as checking an app’s access to specific app capabilities"
Set-Service -Name camsvc -StartupType Manual -Status Stopped -Verbose #Running

Write-Host "This user service is used for Connected Devices Platform scenarios"
Set-Service -Name CDPUserSvc -StartupType Disabled -Status Stopped -Verbose

Write-Host "Copies user certificates and root certificates from smart cards into the current user’s certificate store, detects when a smart card is inserted"
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







Write-host "Coordinates transactions that span multiple resource managers, such as databases, message queues, and file systems"
Set-Service -Name MSDTC -StartupType Auto -Status Running -Verbose

Write-Host "WAP Push Message Routing Service"
Set-Service -Name dmwappushservice -StartupType Disabled -Status Stopped -Verbose

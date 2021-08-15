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










Write-host "Coordinates transactions that span multiple resource managers, such as databases, message queues, and file systems"
Set-Service -Name MSDTC -StartupType Auto -Status Running -Verbose

Write-Host "WAP Push Message Routing Service"
Set-Service -Name dmwappushservice -StartupType Disabled -Status Stopped -Verbose

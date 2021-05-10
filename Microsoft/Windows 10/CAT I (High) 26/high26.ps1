# V-220708
Get-Volume | Where-Object -Property FilesystemType -eq NTFS
Get-Volume | Where-Object -Property FilesystemType -ne NTFS

# V-220706
winver

# V-220707 - The Windows 10 system must use an anti-virus program
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

# V-220932 - Anonymous access to Named Pipes and Shares must be restricted

<# 
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: RestrictNullSessAccess

Value Type: REG_DWORD
Value: 1
Fix Text (F-22636r555282_fix)
Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".
#>

$RestrictNullSessAccess = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess 



if ( $RestrictNullSessAccess.RestrictNullSessAccess -eq 1)
{
    Write-Host V-220932 result is $RestrictNullSessAccess.RestrictNullSessAccess
    Write-Host
    Write-Host "and"
    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess 
}

else
{
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters -Name RestrictNullSessAccess 
Write-Host V-220932 result is $RestrictNullSessAccess.RestrictNullSessAccess
}
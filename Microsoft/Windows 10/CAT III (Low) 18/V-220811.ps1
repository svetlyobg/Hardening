# V-220811 - Virtualization Based Security must be enabled on Windows 10 with the platform security level configured to Secure Boot or Secure Boot with DMA Protection
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220811

$RequiredSecurityProperties = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty RequiredSecurityProperties

 if ( $RequiredSecurityProperties -eq 0 )
        {
            Write-Host "`n$line"
            Write-Host V-220917 result is $RequiredSecurityProperties 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220917 result is $RequiredSecurityProperties
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\'
            } 
# V-220797 - The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220797

$EnableICMPRedirect = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\' | Select -ExpandProperty EnableICMPRedirect

 if ( $EnableICMPRedirect -eq 0 )
        {
            Write-Host "`n$line"
            Write-Host V-220797 result is $EnableICMPRedirect 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220797 result is $EnableICMPRedirect
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\'
            } 
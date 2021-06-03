# V-220798 - The system must be configured to ignore NetBIOS name release requests except from WINS servers
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220798
# Legacy

$NoNameReleaseOnDemand = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\' | Select -ExpandProperty  NoNameReleaseOnDemand

 if ( $NoNameReleaseOnDemand -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-220798 result is $NoNameReleaseOnDemand 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220798 result is $NoNameReleaseOnDemand
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\'
            } 
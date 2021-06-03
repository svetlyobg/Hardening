# V-220918 - The maximum age for machine account passwords must be configured to 30 days or less
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220918

$MaximumPasswordAge = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' | Select -ExpandProperty MaximumPasswordAge

 if ( $DODownloadMode -lt 31 )
        {
            Write-Host "`n$line"
            Write-Host V-220918 result is $MaximumPasswordAge 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220918 result is $MaximumPasswordAge
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\'
            } 
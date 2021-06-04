﻿# V-220917 - The computer account password must not be prevented from being reset
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220917

$DisablePasswordChange = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' | Select -ExpandProperty DisablePasswordChange

 if ( $DisablePasswordChange -eq 0 )
        {
            Write-Host "`n$line"
            Write-Host V-220917 result is $DisablePasswordChange 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220917 result is $DisablePasswordChange
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\'
            } 
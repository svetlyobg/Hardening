# V-220826 - The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220826

$DisableInventory = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\' | Select -ExpandProperty  DisableInventory

 if ( $DisableInventory -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-220826 result is $DisableInventory 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220826 result is $DisableInventory
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\'
            } 
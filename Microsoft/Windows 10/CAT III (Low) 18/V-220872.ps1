# V-220872 - Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220872

$DisableThirdPartySuggestions = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\' | Select -ExpandProperty DisableThirdPartySuggestions

 if ( $DisableInventory -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-220872 result is $DisableThirdPartySuggestions 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\'
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220872 result is $DisableThirdPartySuggestions
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\'
            } 
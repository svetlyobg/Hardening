# V-220825 - The setting to allow Microsoft accounts to be optional for modern style apps must be enabled
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220825

$MSAOptional = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' | Select -ExpandProperty MSAOptional

 if ( $MSAOptional -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-220825 result is $MSAOptional 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\'
            }


    else
            {
                Write-Host "`n$line"
                Write-Host V-220825 result is $MSAOptional
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\'
            } 
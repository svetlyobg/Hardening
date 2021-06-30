# V-220943 - The default permissions of global system objects must be increased
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220943

$ProtectionMode = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\' | Select -ExpandProperty ProtectionMode

function fProtectionMode
$ProtectionMode = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\' | Select -ExpandProperty ProtectionMode

    {
         if ( $ProtectionMode -eq 1 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-220943 result is $ProtectionMode 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-220943 result is $ProtectionMode
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 
    }



if ( $ProtectionMode  -like "True" )
        {
           fProtectionMode

        }
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PushNotifications
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name 'CachedLogonsCount' -Value 10 -PropertyType REG_SZ -Force

        fProtectionMode



    } 


 

 

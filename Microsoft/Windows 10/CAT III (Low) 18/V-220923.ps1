# V-220923 - Caching of logon credentials must be limited
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220923


$CachedLogonsCount = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' | Select -ExpandProperty CachedLogonsCount

function fCachedLogonsCount
{

                    if ( $CachedLogonsCount -gt 0 -and $CachedLogonsCount -lt 11 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-220923 result is $CachedLogonsCount 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-220923 result is $CachedLogonsCount
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\'" -like 'True')

{


if ( $NoToastApplicationNotificationOnLockScreen  -like "True" )
        {
           fCachedLogonsCount
           
           }
}
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name PushNotifications
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name 'CachedLogonsCount' -Value 10 -PropertyType REG_SZ -Force

        fCachedLogonsCount

               

    }
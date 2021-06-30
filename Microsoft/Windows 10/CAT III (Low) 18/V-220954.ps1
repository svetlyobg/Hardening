# V-220954 - Toast notifications to the lock screen must be turned off
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220954

$NoToastApplicationNotificationOnLockScreen = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\' | Select -ExpandProperty NoToastApplicationNotificationOnLockScreen

function check
$NoToastApplicationNotificationOnLockScreen = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\' | Select -ExpandProperty NoToastApplicationNotificationOnLockScreen

{

    if ( $NoToastApplicationNotificationOnLockScreen -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-220954 result is $NoToastApplicationNotificationOnLockScreen 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\'

            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220954 result is $NoToastApplicationNotificationOnLockScreen
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\'

                Write-Host "The Window will close in 5 seconds"
                Start-Sleep -Seconds 5
            } 

}


if ("Test-Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\'" -like 'True')

{


if ( $NoToastApplicationNotificationOnLockScreen -eq 1 )
        {
           check
           
           }
}
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\' -Name PushNotifications
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\' -Name 'NoToastApplicationNotificationOnLockScreen' -Value 1 -PropertyType DWORD -Force

        check

               

    }

 

# V-220857 - The Windows Installer Always install with elevated privileges must be disabled
# https://www.stigviewer.com/stig/windows_10/2020-10-15/finding/V-220857

function f
    {
        Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer"
     }

$AlwaysInstallElevated = f

$AlwaysInstallElevated = f | select -ExpandProperty AlwaysInstallElevated 

    if ( $AlwaysInstallElevated -eq 0 )
        {
            Write-Host "`n$line"
            Write-Host V-220857 result is $AlwaysInstallElevated
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            f
    
        }

    Else
        {
            Write-Host "`n$line"
            Write-Host V-220857 result is $AlwaysInstallElevated
            Write-Host "`n$line"
            Write-Host "This is a finding" -ForegroundColor Red
            f
        }
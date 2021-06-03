# V-220715 - Standard local user accounts must not exist on a system in a domain
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220715


$Enabled = Get-LocalUser | Select -ExpandProperty Enabled


    if ($Enabled -like "True")

    {
        Write-Host "`n$line"
        Write-Host V-220715 result is $Enabled 
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-LocalUser
    }

else

    {
        Write-Host "`n$line"
        Write-Host V-220715 result is $Enabled 
        Write-Host "`n$line"
        Write-Host "This is not a finding" -ForegroundColor Green
        Get-LocalUser
    } 
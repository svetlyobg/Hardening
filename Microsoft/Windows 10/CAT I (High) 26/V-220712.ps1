# V-220712 - Only accounts responsible for the administration of a system must have Administrator rights on the system
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220712

#$hostname = hostname
#$hostname.ToString() | gm
#$LocalGroupMember = Get-LocalGroupMember -Group "Administrators" 
#Get-LocalGroupMember -Group "Administrators" | select -Property PrincipalSource 

$Count = Get-LocalGroupMember -Group "Administrators" | select -Property * | measure | select -ExpandProperty Count

    if ( $Count -eq 0)
{
    Write-Host "`n$line"
    Write-Host V-220712 result is $Count 
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-LocalGroupMember -Group "Administrators" | ft -AutoSize
    Write-Host "`n$line"
    Get-LocalGroupMember -Group "Administrators" | select -Property * | ft -AutoSize
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220712 result is $Count
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-LocalGroupMember -Group "Administrators" | ft -AutoSize
        Write-Host "`n$line"
        Get-LocalGroupMember -Group "Administrators" | select -Property * | ft -AutoSize
    }
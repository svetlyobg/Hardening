# V-220937 - The system must be configured to prevent the storage of the LAN Manager hash of passwords
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220937

$NoLMHash = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa | select -ExpandProperty NoLMHash

if ( $NoLMHash -eq 1)
{
    Write-Host "`n$line"
    Write-Host V-220932 result is $NoLMHash
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name NoLMHash
    
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220932 result is $NoLMHash
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name NoLMHash
    }
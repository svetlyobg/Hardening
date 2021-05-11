# V-220938 - The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220938

$LmCompatibilityLevel = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa | select -ExpandProperty LmCompatibilityLevel

if ( $LmCompatibilityLevel -eq 5)
{
    Write-Host "`n$line"
    Write-Host V-220932 result is $LmCompatibilityLevel
    Write-Host "`n$line"
    Write-Host "This is not a finding" -ForegroundColor Green
    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel
    
}

else
    {
        Write-Host "`n$line"
        Write-Host V-220932 result is $LmCompatibilityLevel
        Write-Host "`n$line"
        Write-Host "This is a finding" -ForegroundColor Red
        Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel
    }
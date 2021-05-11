# V-220727 - Structured Exception Handling Overwrite Protection (SEHOP) must be enabled
# https://www.stigviewer.com/stig/windows_10/2020-10-15/finding/V-220727

function f
    {
        Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
     }

$DisableExceptionChainValidation = f

$t = f | select -Property DisableExceptionChainValidation

    if ( $t.DisableExceptionChainValidation -eq "DisableExceptionChainValidation=null" )
        {
            Write-Host "`n$line"
            Write-Host V-220727 result is $t
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            f
    
        }

    Else
        {
            Write-Host "`n$line"
            Write-Host V-220727 result is $t
            Write-Host "`n$line"
            Write-Host This Key is missing or you need to copt SecGuide.admx and SecGuide.adml must be copied to the Windows-PolicyDefinitions and Windows-PolicyDefinitions-en-US directories respectively. 
            Write-Host "`n$line"
            Write-Host "This is a finding" -ForegroundColor Red
            f
        }
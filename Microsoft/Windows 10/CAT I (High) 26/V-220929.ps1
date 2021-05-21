# V-220929 - Anonymous enumeration of SAM accounts must not be allowed
# https://www.stigviewer.com/stig/windows_10/2020-10-15/finding/V-220929

$RestrictAnonymousSAM = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' | Select -ExpandProperty restrictanonymoussam

    if ($RestrictAnonymousSAM -eq 1)
        {
            Write-Host "`n$line"
            Write-Host V-220929 result is $RestrictAnonymousSAM 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\'
    
        }

    else
        {
            Write-Host "`n$line"
            Write-Host V-220929 result is $RestrictAnonymousSAM
            Write-Host "`n$line"
            Write-Host "This is a finding" -ForegroundColor Red
            Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\'
        }
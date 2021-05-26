# V-220700 - Secure Boot must be enabled on Windows 10 systems
# https://stigviewer.com/stig/windows_10/2020-10-15/finding/V-220700

$ConfirmSecureBootUEFI = Confirm-SecureBootUEFI

    if ( $ConfirmSecureBootUEFI -eq 'True' )
        {
            Write-Host "`n$line"
            Write-Host V-220700 result is $ConfirmSecureBootUEFI 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'Confirm-SecureBootUEF'
        }

    else
        {
            Write-Host "`n$line"
            Write-Host V-220700 result is $ConfirmSecureBootUEFI
            Write-Host "`n$line"
            Write-Host "This is a finding" -ForegroundColor Red
            Confirm-SecureBootUEFI
        }
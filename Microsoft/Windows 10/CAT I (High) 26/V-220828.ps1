# V-220828 - The default autorun behavior must be configured to prevent autorun commands
# https://www.stigviewer.com/stig/windows_10/2020-10-15/finding/V-220828

function f
            {
                Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
            }

$NoAutorun = f | Select -ExpandProperty NoAutorun

    if ( $NoAutorun -eq 1)
                            {
                                Write-Host "`n$line"
                                Write-Host V-220828 result is $NoAutorun 
                                Write-Host "`n$line"
                                Write-Host "This is not a finding" -ForegroundColor Green
                                f
    
                            }

    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-220828 result is $NoAutorun
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                f
                            }

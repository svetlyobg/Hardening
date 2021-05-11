# V-220726 - Data Execution Prevention (DEP) must be configured to at least OptOut
# https://www.stigviewer.com/stig/windows_10/2020-10-15/finding/V-220726

function f
    {
         get-WmiObject Win32_OperatingSystem |  Select-Object DataExecutionPrevention_SupportPolicy -ExpandProperty DataExecutionPrevention_SupportPolicy 
    }

function f2
    {
         wmic OS Get DataExecutionPrevention_SupportPolicy
    }

$dep = f



    if ( $dep -eq 1 -or $dep -eq 3)
                            {
                                Write-Host "`n$line"
                                Write-Host V-220726 result is $dep 
                                Write-Host "`n$line"
                                Write-Host "This is not a finding" -ForegroundColor Green
                                Write-Host "`n$line"
                                f2
    
                            }

    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-220726 result is $dep
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Write-Host "`n$line"
                                f2
                            }


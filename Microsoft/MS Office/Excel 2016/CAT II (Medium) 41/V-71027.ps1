# V-71027 - Files in unsafe locations must be opened in Protected View
# https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71027


$DisableUnsafeLocationsInPV  = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" | Select -ExpandProperty DisableUnsafeLocationsInPV

function fDisableUnsafeLocationsInPV
{

                    $DisableUnsafeLocationsInPV = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" | Select -ExpandProperty DisableUnsafeLocationsInPV

                    if ( $DisableUnsafeLocationsInPV -eq 1 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-71027 result is $DisableUnsafeLocationsInPV 
                            Write-Host "`n$line"
                            Write-Host "This is a finding" -ForegroundColor Red
                            Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-71027 result is $DisableUnsafeLocationsInPV
                                Write-Host "`n$line"
                                Write-Host "This is not a finding" -ForegroundColor Green
                                Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview'" -like 'True')

{


if ( $DisableIntranetCheck  -like "True" )
        {
           fDisableUnsafeLocationsInPV

           }
}
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\' -Name excel
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\' -Name security
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\' -Name protectedview
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview' -Name DisableUnsafeLocationsInPV -Value 0 -PropertyType DWORD -Force

        fDisableUnsafeLocationsInPV



    } 
# V-70973 - Open/Save actions for Excel 2 macrosheets and add-in files must be blocked
# https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70973


$XL2Macros  = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" | Select -ExpandProperty XL2Macros

function fXL2Macros
{

                    $XL2Macros = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" | Select -ExpandProperty XL2Macros

                    if ( $XL2Macros -eq 2 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-70973 result is $XL2Macros 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-70973 result is $XL2Macros
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock'" -like 'True')

{


if ( $XL2Macros  -like "True" )
        {
           fXL2Macros

           }
}
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\' -Name excel
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\' -Name security
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\' -Name fileblock
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock' -Name XL2Macros -Value 2 -PropertyType DWORD -Force

        fXL2Macros



    } 
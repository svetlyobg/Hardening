# V-70977 - Open/Save actions for Excel 3 macrosheets and add-in files must be blocked
# https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70977


$XL3Macros = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" | Select -ExpandProperty XL3Macros

function fXL3Macros
{

                    $XL3Macros = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" | Select -ExpandProperty XL3Macros

                    if ( $XL3Macros -eq 2 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-70977 result is $XL3Macros 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-70977 result is $XL3Macros
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock'" -like 'True')

{


if ( $XL3Macros  -like "True" )
        {
           fXL3Macros

           }
}
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\' -Name excel
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\' -Name security
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security' -Name fileblock
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock' -Name XL3Macros -Value 2 -PropertyType DWORD -Force

        fXL3Macros



    } 
# V-70987 - Files from the Internet zone must be opened in Protected View
# https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70987


$DisableInternetFilesInPV  = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" | Select -ExpandProperty DisableInternetFilesInPV

function fDisableInternetFilesInPV
{

                    $DisableInternetFilesInPV = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" | Select -ExpandProperty DisableInternetFilesInPV

                    if ( $DisableInternetFilesInPV -eq 0 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-70987 result is $DisableInternetFilesInPV 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }
                    elseif ( $DisableInternetFilesInPV -eq 1 )
                    {
                                Write-Host "`n$line"
                                Write-Host V-70987 result is $DisableInternetFilesInPV
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-70987 result is $DisableInternetFilesInPV
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview'" -like 'True')

{


if ( $DisableInternetFilesInPV  -like "True" )
        {
           fDisableInternetFilesInPV

           }
}
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\' -Name excel
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\' -Name security
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\' -Name protectedview
       
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview' -Name DisableInternetFilesInPV -Value 0 -PropertyType DWORD -Force

        fDisableInternetFilesInPV



    } 
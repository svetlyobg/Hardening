# V-71025 - ActiveX Installs must be configured for proper restriction
# https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71025


$excel  = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" | Select -ExpandProperty 'excel.exe'

function fexcel
{

                    $excel = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" | Select -ExpandProperty 'excel.exe'

                    if ( $excel -eq 1 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-71025 result is $excel 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-71025 result is $excel
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'" -like 'True')

{


if ( $excel  -like "True" )
        {
           fexcel

           }
}
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\' -Name FEATURE_RESTRICT_ACTIVEXINSTALL
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL' -Name 'excel.exe' -Value 1 -PropertyType DWORD -Force

        fexcel



    }
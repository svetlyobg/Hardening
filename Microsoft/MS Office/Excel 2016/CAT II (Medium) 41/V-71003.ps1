# V-71003 - File Downloads must be configured for proper restrictions
# https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71003


$excel = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" | Select -ExpandProperty 'excel.exe'

function fexcel
{

                    $excel = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" | Select -ExpandProperty 'excel.exe'

                    if ( $excel -eq 1 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-70997 result is $excel 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-70997 result is $excel
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'" -like 'True')

{


if ( $excel  -like "True" )
        {
           fexcel

           }
}
else 

    {
       

        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD' -Name 'excel.exe' -Value 1 -PropertyType DWORD -Force

        fexcel



    } 
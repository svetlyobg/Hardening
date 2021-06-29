# V-70997 - Add-ins to Office applications must be signed by a Trusted Publisher
# https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70997


$RequireAddinSig  = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security" | Select -ExpandProperty RequireAddinSig

function fRequireAddinSig
{

                    $RequireAddinSig = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security" | Select -ExpandProperty RequireAddinSig

                    if ( $RequireAddinSig -eq 1 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-70997 result is $RequireAddinSig 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-70997 result is $RequireAddinSig
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security'" -like 'True')

{


if ( $RequireAddinSig  -like "True" )
        {
           fRequireAddinSig

           }
}
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\' -Name excel
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\' -Name security
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security' -Name RequireAddinSig -Value 1 -PropertyType DWORD -Force

        fRequireAddinSig



    } 
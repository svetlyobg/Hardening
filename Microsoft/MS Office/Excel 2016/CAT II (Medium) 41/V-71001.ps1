# V-71001 - Trust Bar Notifications for unsigned application add-ins must be blocked
# https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71001


$NoTBPromptUnsignedAddin = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security" | Select -ExpandProperty NoTBPromptUnsignedAddin

function fNoTBPromptUnsignedAddin
{

                    $NoTBPromptUnsignedAddin = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security" | Select -ExpandProperty NoTBPromptUnsignedAddin

                    if ( $NoTBPromptUnsignedAddin -eq 1 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-71001 result is $NoTBPromptUnsignedAddin 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-71001 result is $excel
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security'" -like 'True')

{


if ( $excel  -like "True" )
        {
           fNoTBPromptUnsignedAddin

           }
}
else 

    {
       

        New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security' -Name NoTBPromptUnsignedAddin -Value 1 -PropertyType DWORD -Force

        fNoTBPromptUnsignedAddin



    } 
<#
.SYNOPSIS
    V-70971 - Open/Save actions for Dif and Sylk files must be blocked

.DESCRIPTION
    This policy setting allows you to determine whether users can open, view, edit, or save Excel files with the format specified by the title of this policy setting. If you enable this policy setting, you can specify whether users can open, view, edit, or save files. The options that can be selected are below. Note: Not all options may be available for this policy setting.- Do not block: The file type will not be blocked.- Save blocked: Saving of the file type will be blocked.- Open/Save blocked, use open policy: Both opening and saving of the file type will be blocked. The file will open based on the policy setting configured in the "default file block behavior" key.- Block: Both opening and saving of the file type will be blocked, and the file will not open.- Open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit the file type will not be enabled.- Allow editing and open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit will be enabled. If you disable or do not configure this policy setting, the file type will not be blocked.

.LINK
    https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70971
#>



$DifandSylkFiles  = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" | Select -ExpandProperty DifandSylkFiles

function fDifandSylkFiles


{

                    $DifandSylkFiles = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" | Select -ExpandProperty DifandSylkFiles

                    if ( $DifandSylkFiles -eq 2 )
                        {
                            Write-Host "`n$line"
                            Write-Host V-70971 result is $DifandSylkFiles 
                            Write-Host "`n$line"
                            Write-Host "This is not a finding" -ForegroundColor Green
                            Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock'

                            Write-Host "The Window will close in 5 seconds"
                            Start-Sleep -Seconds 5
                            }

                    else
                            {
                                Write-Host "`n$line"
                                Write-Host V-70971 result is $DifandSylkFiles
                                Write-Host "`n$line"
                                Write-Host "This is a finding" -ForegroundColor Red
                                Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock'

                                Write-Host "The Window will close in 5 seconds"
                                Start-Sleep -Seconds 5
                            } 

                }


if ("Test-Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock'" -like 'True')

{


if ( $DifandSylkFiles  -like "True" )
        {
           fDifandSylkFiles

           }
}
else 

    {
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock\' -ItemType Directory
        Write-Host Path Created -ForegroundColor Green 
        New-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock' -Name DifandSylkFiles -Value 2 -PropertyType DWORD -Force
        $DifandSylkFiles  = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" | Select -ExpandProperty DifandSylkFiles

        fDifandSylkFiles



    }
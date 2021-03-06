<#
.SYNOPSIS
     V-228449 - Object Model Prompt behavior for the SaveAs method must be configured

.DESCRIPTION
    This policy setting controls what happens when an untrusted program attempts to use the Save As command to programmatically save an item. If you enable this policy setting, you can choose from four different options when an untrusted program attempts to use the Save As command to programmatically save an item:- Prompt user. The user will be prompted to approve every access attempt. - Automatically approve. Outlook will automatically grant programmatic access requests from any program. This option can create a significant vulnerability, and is not recommended. - Automatically deny. Outlook will automatically deny programmatic access requests from any program.- Prompt user based on computer security. Outlook will only prompt users when antivirus software is out of date or not running. This is the default configuration. If you disable or do not configure this policy setting, when an untrusted application attempts to use the Save As command, Outlook relies on the setting configured in the 'Programmatic Access' section of the Trust Center. 

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228449
#>

$path = 'HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security'
$regname = 'PromptOOMSaveAs'
$regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty $regname


function fcheckpath
{Test-Path $path}

function fcreate
{
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path $path -ItemType Directory
        Write-Host Path Created -ForegroundColor Green
        New-ItemProperty -Path $path -Name $regname -Value 0 -PropertyType DWORD -Force
        Write-Host Registry Created and Set Up -ForegroundColor Green

}

function fcheckreg 
    {
    $regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty $regname
        if ( $regvalue -eq 0 )
        {
            Write-Host "`n$line"
            Write-Host  V-228449 result is $regvalue 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path $path
            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host  V-228449 result is $regvalue
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path $path
                Write-Host "The Window will close in 5 seconds"
                Start-Sleep -Seconds 5
            } 
    }


if ("Test-Path $path" -like "True")
{
    Write-Host $path
    fcreate
    fcheckreg
}

else {
        Write-Host $path
        fcreate
     }


    
if (fcheckpath -like 'True' )
{fcreate
 fcheckreg}
else{fcheckreg}
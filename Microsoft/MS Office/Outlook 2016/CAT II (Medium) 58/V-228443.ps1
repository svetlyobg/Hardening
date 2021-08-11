<#
.SYNOPSIS
      V-228443 - Scripts in One-Off Outlook forms must be disallowed

.DESCRIPTION
    This policy setting controls whether scripts can run in Outlook forms in which the script and layout are contained within the message. If you enable this policy setting, scripts can run in one-off Outlook forms. If you disable or do not configure this policy setting, Outlook does not run scripts in forms in which the script and the layout are contained within the message. Important: This policy setting only applies if the "Outlook Security Mode" policy setting under "Microsoft Outlook 2016\Security\Security Form Settings" is configured to "Use Outlook Security Group Policy." 

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228443
#>

$path = 'HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security'
$regname = 'EnableOneOffFormScripts'
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
            Write-Host   V-228443 result is $regvalue 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path $path
            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host   V-228443 result is $regvalue
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
<#
.SYNOPSIS
     V-228428 - ActiveX Installs must be configured for proper restriction

.DESCRIPTION
    Microsoft ActiveX controls allow unmanaged, unprotected code to run on the user computers.
    ActiveX controls do not run within a protected container in the browser like the other types of HTML or Microsoft Silverlight-based controls.
    Disabling or not configuring this setting does not block prompts for ActiveX control installations, and these prompts display to users.
    This could allow malicious code to become active on user computers or the network.

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228428
#>

$path = 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'


function fcheckpath
{Test-Path $path}

function fcreate
{
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path $path -ItemType Directory
        Write-Host Path Created -ForegroundColor Green
        New-ItemProperty -Path $path -Name $regname -Value 1 -PropertyType DWORD -Force
        Write-Host Registry Created and Set Up -ForegroundColor Green

}

function fcheckreg 
    {
    $regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty $regname
        if ( $regvalue -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host  V-228428 result is $regvalue 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path $path
            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host  V-228428 result is $regvalue
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

}

else {
        Write-Host $path
        fcreate
}


$regname = 'outlook.exe '
$regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty $regname

    
if (fcheckpath -like 'True' )
{fcreate
 fcheckreg}
else{fcheckreg}
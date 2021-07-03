<#
.SYNOPSIS
     V-228429 - Publishing calendars to Office Online must be prevented

.DESCRIPTION
    This policy setting controls whether Outlook users can publish their calendars to the Office.com Calendar Sharing Service. 
    If you enable this policy setting, Outlook users cannot publish their calendars to Office.com. 
    If you disable do not configure this policy setting, Outlook users can share their calendars with selected others by publishing them to the Microsoft Outlook Calendar Sharing Service. 
    Users can control who can view their calendar and at what level of detail.

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228429
#>

$path16 = 'HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal'
$path15 = 'HKCU:\Software\Policies\Microsoft\Office\15.0\outlook\options\pubcal'
$path15main = 'HKCU:\Software\Policies\Microsoft\Office\15.0\'
$path16main = 'HKCU:\Software\Policies\Microsoft\Office\16.0\'


if ("Test-Path $path16main" -like "True")
{$pathmain = $path16main 
    Write-Host $pathmain
    $path = $path16
    fcreate

}
else {$pathmain = $path15main
     Write-Host $pathmain
    $path = $path15
    fcreate
}

$regname = 'DisableOfficeOnline'
$regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty $regname


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
            Write-Host  V-228429 result is $regvalue 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path $path
            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host  V-228429 result is $regvalue
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path $path
                Write-Host "The Window will close in 5 seconds"
                Start-Sleep -Seconds 5
            } 
    }
    
if (fcheckpath -like 'True' )
{fcreate
 fcheckreg}
else{fcheckreg}
<#
.SYNOPSIS
     V-228425 - Links that invoke instances of Internet Explorer from within an Office product must be blocked

.DESCRIPTION
    The Pop-up Blocker feature in Internet Explorer can be used to block most unwanted pop-up and pop-under windows from appearing. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If the Pop-up Blocker is disabled, disruptive and potentially dangerous pop-up windows could load and present a security risk

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228425
#>

$path = 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT\'
$regname = 'outlook.exe'
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
            Write-Host  V-228425 result is $regvalue 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path $path
            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host  V-228425 result is $regvalue
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
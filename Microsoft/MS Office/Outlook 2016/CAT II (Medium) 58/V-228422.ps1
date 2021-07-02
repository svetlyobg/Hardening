<#
.SYNOPSIS
     V-228422 - Navigation to URLs embedded in Office products must be blocked

.DESCRIPTION
    To protect users from attacks, Internet Explorer usually does not attempt to load malformed URLs. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If Internet Explorer attempts to load a malformed URL, a security risk could occur. 

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228422
#>

$path = 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL\'
$regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty 'outlook.exe'


function fcheckpath
{Test-Path $path}

function fcreate
{
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path $path -ItemType Directory
        Write-Host Path Created -ForegroundColor Green
        New-ItemProperty -Path $path -Name 'outlook.exe' -Value 1 -PropertyType DWORD -Force
        Write-Host Registry Created and set up -ForegroundColor Green

}

function fcheckreg 
    {
    $regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty 'outlook.exe'
        if ( $regvalue -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host  V-228422 result is $regvalue 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path $path
            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host  V-228422 result is $regvalue
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
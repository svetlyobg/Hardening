<#
.SYNOPSIS
     V-228426 - File Downloads must be configured for proper restrictions

.DESCRIPTION
    Disabling this setting allows websites to present file download prompts via code without the user specifically initiating the download. 
    User preferences may also allow the download to occur without prompting or interaction with the user. 
    Even if Internet Explorer prompts the user to accept the download, some websites abuse this functionality. 
    Malicious websites may continually prompt users to download a file or present confusing dialog boxes to trick users into downloading or running a file. 
    If the download occurs and it contains malicious code, the code could become active on user computers or the network.

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228426
#>

$path = 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\'
$regname = 'outlook.exe'
$regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty $regname


function fcheckpath
{Test-Path $path}

function fcreate
{
        Write-Host Path Does Not Exist -ForegroundColor Red
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
            Write-Host  V-228426 result is $regvalue 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path $path
            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host  V-228426 result is $regvalue
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
<#
.SYNOPSIS
    V-228423 - Scripted Window Security must be enforced

.DESCRIPTION
    Malicious websites often try to confuse or trick users into giving a site permission to perform an action allowing the site to take control of the users' computers in some manner. Disabling or not configuring this setting allows unknown websites to: -Create browser windows appearing to be from the local operating system. -Draw active windows displaying outside of the viewable areas of the screen capturing keyboard input. -Overlay parent windows with their own browser windows to hide important system information, choices or prompts

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228423
#>

$outlook = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\' | Select -ExpandProperty 'outlook.exe'
$path = 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\'

function fcheckpath

{
   Test-Path $path

}

function fcreate

{
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\' -ItemType Directory
        Write-Host Path Created -ForegroundColor Green
        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\' -Name 'outlook.exe' -Value 1 -PropertyType DWORD -Force

}

function fcheckreg 

    {

    $outlook = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\' | Select -ExpandProperty 'outlook.exe'

        if ( $outlook -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-228423 result is $outlook 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\'

            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-228423 result is $outlook
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\'



                Write-Host "The Window will close in 5 seconds"
                Start-Sleep -Seconds 5
            } 
    }
    
if (fcheckpath -like 'True' )
{               
       fcreate
       fcheckreg
 }

else

{   
        
        fcheckreg
}
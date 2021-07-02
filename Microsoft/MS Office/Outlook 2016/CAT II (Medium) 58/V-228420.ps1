<#
.SYNOPSIS
    V-228420 - Enabling IE Bind to Object functionality must be present

.DESCRIPTION
    Internet Explorer performs a number of safety checks before initializing an ActiveX control. It will not initialize a control if the kill bit for the control is set in the registry, or if the security settings for the zone in which the control is located do not allow it to be initialized. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). A security risk could occur if potentially dangerous controls are allowed to load. 

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228420
#>

$FEATURE_SAFE_BINDTOOBJECT = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT\' | Select -ExpandProperty FEATURE_SAFE_BINDTOOBJECT

function fFEATURE_SAFE_BINDTOOBJECT 

    {

    $FEATURE_SAFE_BINDTOOBJECT = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT\' | Select -ExpandProperty FEATURE_SAFE_BINDTOOBJECT

        if ( $FEATURE_SAFE_BINDTOOBJECT -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-228420 result is $FEATURE_SAFE_BINDTOOBJECT 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT\'

            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-228420 result is $FEATURE_SAFE_BINDTOOBJECT
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT\'

                Write-Host "The Window will close in 5 seconds"
                Start-Sleep -Seconds 5
            } 
    }
    
if ("Test-Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT\'" -like 'True' )
{
    if ($FEATURE_SAFE_BINDTOOBJECT -like "True")

    {
        fFEATURE_SAFE_BINDTOOBJECT
    }
}

else

{
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT\' -ItemType Directory
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT\' -Name FEATURE_SAFE_BINDTOOBJECT -Value 1 -PropertyType DWORD -Force

        fFEATURE_SAFE_BINDTOOBJECT
}
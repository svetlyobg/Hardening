<#
.SYNOPSIS
    V-228421 - Saved from URL mark to assure Internet zone processing must be enforced

.DESCRIPTION
    Typically, when Internet Explorer loads a web page from a Universal Naming Convention (UNC) share that contains a Mark of the Web (MOTW) comment, indicating the page was saved from a site on the Internet, Internet Explorer runs the page in the Internet security zone instead of the less restrictive Local Intranet security zone. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If Internet Explorer does not evaluate the page for a MOTW, potentially dangerous code could be allowed to run.

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228421
#>

$FEATURE_UNC_SAVEDFILECHECK = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK\' | Select -ExpandProperty FEATURE_UNC_SAVEDFILECHECK

function fFEATURE_UNC_SAVEDFILECHECK 

    {

    $FEATURE_UNC_SAVEDFILECHECK = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK\' | Select -ExpandProperty FEATURE_UNC_SAVEDFILECHECK

        if ( $FEATURE_UNC_SAVEDFILECHECK -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-228421 result is $FEATURE_UNC_SAVEDFILECHECK 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK\'

            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-228421 result is $FEATURE_UNC_SAVEDFILECHECK
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK\'

                Write-Host "The Window will close in 5 seconds"
                Start-Sleep -Seconds 5
            } 
    }
    
if ("Test-Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK\'" -like 'True' )
{
    if ($FEATURE_UNC_SAVEDFILECHECK -like "True")

    {
        fFEATURE_UNC_SAVEDFILECHECK
    }
}

else

{
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK\' -ItemType Directory
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK\' -Name FEATURE_UNC_SAVEDFILECHECK -Value 1 -PropertyType DWORD -Force

        fFEATURE_UNC_SAVEDFILECHECK
}
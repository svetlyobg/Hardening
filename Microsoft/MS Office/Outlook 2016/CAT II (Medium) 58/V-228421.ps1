# V-228421 - Saved from URL mark to assure Internet zone processing must be enforced
# https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228421

$FEATURE_UNC_SAVEDFILECHECK = Get-ItemProperty -Path 'HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\'FEATURE_UNC_SAVEDFILECHECK\' | Select -ExpandProperty FEATURE_UNC_SAVEDFILECHECK

function fFEATURE_UNC_SAVEDFILECHECK

    {
        if ( $FEATURE_UNC_SAVEDFILECHECK -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-228421 result is $FEATURE_UNC_SAVEDFILECHECK 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK\'

            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-228421 result is $FEATURE_UNC_SAVEDFILECHECK
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\'

                Write-Host "The Window will close in 5 seconds"
                Start-Sleep -Seconds 5
            } 
    }
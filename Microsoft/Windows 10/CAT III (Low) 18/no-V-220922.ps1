# V-220922 - The Windows dialog box title for the legal banner must be configured
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220922

$LegalNoticeCaption = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' | Select -ExpandProperty LegalNoticeCaption

function LegalNoticeCaptionCheck

$LegalNoticeCaption = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' | Select -ExpandProperty LegalNoticeCaption

{

      if ( $LegalNoticeCaption -eq 1 )
        {
            Write-Host "`n$line"
            Write-Host V-220922 result is $LegalNoticeCaption 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\'

            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host V-220922 result is $LegalNoticeCaption
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\'

                Write-Host "The Window will close in 5 seconds"
                Start-Sleep -Seconds 5
            } 



}

if ("Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\'" -like 'True')

{
    LegalNoticeCaptionCheck
}

else

{
    Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name PushNotifications
        Write-Host Path Created -ForegroundColor Green

        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name 'LegalNoticeCaption' -Value "DoD Notice and Consent Banner" -PropertyType REG_SZ -Force

        LegalNoticeCaptionCheck
}

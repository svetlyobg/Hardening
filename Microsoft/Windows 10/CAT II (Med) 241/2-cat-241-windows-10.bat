rem V-220709 - Alternate operating systems must not be permitted on the same system
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220709
rem manual check
rem Run "Advanced System Settings".
rem Select the "Advanced" tab.
rem Click the "Settings" button in the "Startup and Recovery" section.
rem If the drop-down list box "Default operating system:" shows any operating system other than Windows 10, this is a finding.

rem V-220830 - Enhanced anti-spoofing for facial recognition must be enabled on Window 10.
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220830
reg add "HKLM\Software\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
echo enabled "V-220830 - Enhanced anti-spoofing for facial recognition must be enabled on Window 10"

rem V-220836 - The Windows Defender SmartScreen for Explorer must be enabled.
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220836
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f



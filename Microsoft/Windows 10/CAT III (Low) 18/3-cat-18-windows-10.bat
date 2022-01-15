reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v MSAOptional /t REG_DWORD /d 1 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 30 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 0 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LegalNoticeCaption /t REG_SZ /d "DoD Notice and Consent Banner" /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d "10" /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
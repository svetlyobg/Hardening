rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-77967
rem V-77967 - Windows Defender AV must be configured block Office applications from creating child processes
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v D4F940AB-401B-4EFC-AADC-AD5F3C50688A /t REG_SZ /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-77965
rem V-77965 - Windows Defender AV must be configured to block executable content from email client and webmail
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 /t REG_SZ /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-77969
rem V-77969 - Windows Defender AV must be configured block Office applications from creating executable content
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 3B576869-A4EC-4529-8536-B80A7769E899 /t REG_SZ /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75239
rem V-75239 - Windows Defender AV must be configured to turn on e-mail scanning
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v DisableEmailScanning /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75219
rem V-75219 - Windows Defender AV Group Policy settings must take priority over the local preference settings
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v LocalSettingOverrideDisableRealtimeMonitoring /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75217
rem V-75217 - Windows Defender AV must be configured to not allow override of behavior monitoring
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v LocalSettingOverrideDisableBehaviorMonitoring /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75161
rem V-75161 - Windows Defender AV must be configured to disable local setting override for reporting to Microsoft MAPS
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v Spynet /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75215
rem V-75215 - Windows Defender AV must be configured to not allow override of scanning for downloaded files and attachments
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v LocalSettingOverrideDisableIOAVProtection /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75231
rem V-75231 - Windows Defender AV must be configured to process scanning when real-time protection is enabled
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75213
rem V-75213 - Windows Defender AV must be configured to not allow override of monitoring for incoming and outgoing file activity
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v LocalSettingOverrideRealtimeScanDirection /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75211
rem V-75211 - Windows Defender AV must be configured to not allow local override of monitoring for file and program activity
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v LocalSettingOverrideDisableOnAccessProtection /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-79971
rem V-79971 - Windows Defender AV must be configured for automatic remediation action to be taken for threat alert level Low
rem  Valid threat alert levels are: 1 = Low 2 = Medium 4 = High 5 = Severe Valid remediation action values are: 2 = Quarantine 3 = Remove 6 = Ignore 
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v 1 /t REG_SZ /d 2 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75159
rem V-75159 - Windows Defender AV must be configured to enable the Automatic Exclusions feature
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v DisableAutoExclusions /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75163
rem V-75163 - Windows Defender AV must be configured to check in real time with MAPS before content is run or accessed
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75227
rem V-75227 - Windows Defender AV must be configured to always enable real-time protection
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75151
rem V-75151 - Windows Defender AV must be configured to automatically take action on all detected tasks
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableRoutinelyTakingAction /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75155
rem V-75155 - Windows Defender AV must be configured to not exclude files for scanning
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v Exclusions_Paths /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75157
rem V-75157 - Windows Defender AV must be configured to not exclude files opened by specified processes
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v Exclusions_Processes /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-77975
rem V-77975 - Windows Defender AV must be configured to block execution of potentially obfuscated scripts
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC /t REG_SZ /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75225
rem V-75225 - Windows Defender AV must be configured to scan all downloaded files and attachments
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-77971
rem V-77971 - Windows Defender AV must be configured to block Office applications from injecting into other processes
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 /t REG_SZ /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-77973
rem V-77973 - Windows Defender AV must be configured to impede JavaScript and VBScript to launch executables
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v D3E037E1-3EB8-44C8-A917-57927947596D /t REG_SZ /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-77979
rem V-77979 - Windows Defender AV must be configured to prevent user and apps from accessing dangerous websites
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v EnableNetworkProtection /t REG_DWORD /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75223
rem V-75223 - Windows Defender AV must be configured to monitor for file and program activity
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75209
rem V-75209 - Windows Defender AV must be configured for protocol recognition for network protection
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS" /v DisableProtocolRecognition /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75245
rem V-75245 - Windows Defender AV must be configured to check for definition updates daily
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Update" /v ScheduleDay /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75221
rem V-75221 - Windows Defender AV must monitor for incoming and outgoing files
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v RealtimeScanDirection /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75235
rem V-75235 - Windows Defender AV must be configured to scan removable drives
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v DisableRemovableDriveScanning /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75247
rem V-75247 - Windows Defender AV must be configured for automatic remediation action to be taken for threat alert level Severe
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v 5 /t REG_SZ /d 2 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75229
rem V-75229 - Windows Defender AV must be configured to enable behavior monitoring
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75167
rem V-75167 - Windows Defender AV must be configured to join Microsoft MAPS
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 2 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-77977
rem V-77977 - Windows Defender AV must be configured to block Win32 imports from macro code in Office
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B /t REG_SZ /d 1 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-79965
rem V-79965 - Windows Defender AV must be configured for automatic remediation action to be taken for threat alert level High
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v 4 /t REG_SZ /d 2 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75237
rem V-75237 - Windows Defender AV must be configured to perform a weekly scheduled scan
rem 0 - everyday; 1 monday; ..etc ... ; 8 - never
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v ScheduleDay /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-79967
rem V-79967 - Windows Defender AV must be configured for automatic remediation action to be taken for threat alert level Medium
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v 2 /t REG_SZ /d 2 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75233
rem V-75233 - Windows Defender AV must be configured to scan archive files
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v DisableArchiveScanning /t REG_DWORD /d 0 /f

rem https://stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75207
rem V-75207 - Windows Defender AV must be configured to only send safe samples for MAPS telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 1 /f
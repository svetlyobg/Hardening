rem V-70997 - Add-ins to Office applications must be signed by a Trusted Publisher
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70997
reg add HKCU\Software\Policies\Microsoft\Office\16.0\excel\security /v RequireAddinSig /t REG_DWORD /d 1 /f

rem V-70995 - Add-on Management functionality must be allowed
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70995
reg add HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT /v excel.exe /t REG_DWORD /d 1 /f

rem V-70993 - Scripted Window Security must be enforced
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70993
reg add HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS /v excel.exe /t REG_DWORD /d 1 /f

rem V-70991 - Navigation to URLs embedded in Office products must be blocked
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70991
reg add HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL /v excel.exe /t REG_DWORD /d 1 /f

rem V-70999 - Links that invoke instances of Internet Explorer from within an Office product must be blocked
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70999
reg add HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT /v excel.exe /t REG_DWORD /d 1 /f

rem V-71015 - The scanning of encrypted macros in open XML documents must be enforced
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71015
reg add HKCU\Software\Policies\Microsoft\Office\16.0\excel\security /v ExcelBypassEncryptedMacroScan /t REG_DWORD /d 0 /f

rem V-71017 - Macro storage must be in personal macro workbooks
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71017
reg add HKCU\Software\Policies\Microsoft\Office\16.0\excel\options\binaryoptions /v fGlobalSheet_37_1 /t REG_DWORD /d 1 /f

rem V-71011 - The Save commands default file format must be configured
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71011
reg add HKCU\Software\Policies\Microsoft\Office\16.0\excel\options /v DefaultFormat /t REG_DWORD /d 51 /f

rem V-71019 - Trust access for VBA must be disallowed
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71019
reg add HKCU\Software\Policies\Microsoft\Office\16.0\excel\security /v AccessVBOM /t REG_DWORD /d 0 /f

rem V-71039 - Macros must be blocked from running in Office files from the Internet
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71039
reg add HKCU\Software\Policies\Microsoft\Office\16.0\excel\security /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f

rem V-70969 - Enabling IE Bind to Object functionality must be present
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70969
reg add HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT /v excel.exe /t REG_DWORD /d 1 /f

rem V-71033 - Enabling IE Bind to Object functionality must be present
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71033
reg add HKCU\software\policies\Microsoft\office\16.0\excel\security /v vbawarnings /t REG_DWORD /d 2 /f
rem Values of REG_DWORD = 3 or 4 are also acceptable values


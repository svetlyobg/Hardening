rem V-70997 - Add-ins to Office applications must be signed by a Trusted Publisher
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70997
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security" /v RequireAddinSig /t REG_DWORD /d 1 /f

rem V-70995 - Add-on Management functionality must be allowed
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70995
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" /v excel.exe /t REG_DWORD /d 1 /f

rem V-70993 - Scripted Window Security must be enforced
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70993
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" /v excel.exe /t REG_DWORD /d 1 /f

rem V-70991 - Navigation to URLs embedded in Office products must be blocked
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70991
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" /v excel.exe /t REG_DWORD /d 1 /f

rem V-70999 - Links that invoke instances of Internet Explorer from within an Office product must be blocked
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70999
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" /v excel.exe /t REG_DWORD /d 1 /f

rem V-71015 - The scanning of encrypted macros in open XML documents must be enforced
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71015
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security" /v ExcelBypassEncryptedMacroScan /t REG_DWORD /d 0 /f

rem V-71017 - Macro storage must be in personal macro workbooks
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71017
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\options\binaryoptions" /v fGlobalSheet_37_1 /t REG_DWORD /d 1 /f

rem V-71011 - The Save commands default file format must be configured
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71011
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\options" /v DefaultFormat /t REG_DWORD /d 51 /f

rem V-71019 - Trust access for VBA must be disallowed
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71019
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security" /v AccessVBOM /t REG_DWORD /d 0 /f

rem V-71039 - Macros must be blocked from running in Office files from the Internet
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71039
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f

rem V-70969 - Enabling IE Bind to Object functionality must be present
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70969
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" /v excel.exe /t REG_DWORD /d 1 /f

rem V-71033 - Enabling IE Bind to Object functionality must be present
rem https://stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71033
reg add "HKCU\software\policies\Microsoft\office\16.0\excel\security" /v vbawarnings /t REG_DWORD /d 2 /f
rem Values of REG_DWORD = 3 or 4 are also acceptable values

rem V-70963 - Actions for Excel 95 workbooks must be configured to edit in Protected View
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70963
reg add "HKCU\software\policies\Microsoft\office\16.0\excel\security\fileblock" /v fileblock /t REG_DWORD /d 5 /f

rem V-71031 - Excel attachments opened from Outlook must be in Protected View
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71031
reg add "HKCU\software\policies\Microsoft\office\16.0\excel\security\protectedview" /v DisableAttachmentsInPV /t REG_DWORD /d 0 /f

rem V-70961 - Open/Save actions for Excel 4 worksheets must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70961
reg add "HKCU\software\policies\Microsoft\office\16.0\excel\security\fileblock" /v XL4Worksheets /t REG_DWORD /d 2 /f

rem V-71037 - Corrupt workbook options must be disallowed
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71037
reg add "HKCU\software\policies\Microsoft\office\16.0\excel\options" /v extractdatadisableui /t REG_DWORD /d 1 /f

rem V-70967 - Blocking as default file block opening behavior must be enforced
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70967
reg add "HKCU\software\policies\Microsoft\office\16.0\excel\fileblock" /v OpenInProtectedView /t REG_DWORD /d 0 /f

rem V-71035 - WEBSERVICE functions must be disabled
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71035
reg delete "HKCU\software\policies\Microsoft\office\16.0\excel\security" /v webservicefunctionwarnings /f
rem reg add HKCU\software\policies\Microsoft\office\16.0\excel\security /v webservicefunctionwarnings /t REG_DWORD /d 1 /f

rem V-70965 - Actions for Excel 95-97 workbooks and templates must be configured to edit in Protected View
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70965
reg add "HKCU\Software\Policies\Microsoft\office\16.0\excel\security\fileblock" /v XL9597WorkbooksandTemplates /t REG_DWORD /d 5 /f

rem V-70985 - Open/Save actions for web pages and Excel 2003 XML spreadsheets must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70985
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" /v HtmlandXmlssFiles /t REG_DWORD /d 2 /f

rem V-70987 - Files from the Internet zone must be opened in Protected View
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70987
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" /v DisableInternetFilesInPV /t REG_DWORD /d 0 /f
rem reg delete HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview /v DisableInternetFilesInPV /f

rem V-70981 - Saved from URL mark to assure Internet zone processing must be enforced
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70981
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" /v excel.exe /t REG_DWORD /d 1 /f

rem V-70983 - Configuration for file validation must be enforced
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70983
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation" /v EnableOnLoad /t REG_DWORD /d 1 /f

rem V-70989 - Open/Save actions for dBase III / IV files must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70989
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" /v DBaseFiles /t REG_DWORD /d 2 /f

rem V-71003 - File Downloads must be configured for proper restrictions
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71003
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" /v excel.exe /t REG_DWORD /d 1 /f

rem V-71001 - Trust Bar Notifications for unsigned application add-ins must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71001
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security" /v NoTBPromptUnsignedAddin /t REG_DWORD /d 1 /f

rem V-71007 - Disallowance of trusted locations on the network must be enforced
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71007
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations" /v AllowNetworkLocations /t REG_DWORD /d 0 /f

rem V-71005 - All automatic loading from trusted locations must be disabled
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71005
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\trusted locations" /v AllLocationsDisabled /t REG_DWORD /d 1 /f

rem V-70957 - Open/Save actions for Excel 4 macrosheets and add-in files must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70957
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" /v AllLocationsDisabled /t REG_DWORD /d 1 /f

rem V-71029 - Document behavior if file validation fails must be set
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71029
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation" /v DisableEditFromPV /t REG_DWORD /d 1 /f
rem reg delete add HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\filevalidation /v DisableEditFromPV /f

rem V-70979 - Open/Save actions for Excel 3 worksheets must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70979
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" /v XL3Worksheets /t REG_DWORD /d 2 /f

rem V-70955 - Disabling of user name and password syntax from being used in URLs must be enforced
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70955
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" /v excel.exe /t REG_DWORD /d 1 /f

rem V-70975 - Open/Save actions for Excel 2 worksheets must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70975
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" /v XL2Worksheets /t REG_DWORD /d 2 /f

rem V-70959 - Open/Save actions for Excel 4 workbooks must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70959
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" /v XL4Workbooks /t REG_DWORD /d 2 /f

rem V-71023 - Protection from zone elevation must be enforced
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71023
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" /v excel.exe /t REG_DWORD /d 1 /f

rem V-70971 - Open/Save actions for Dif and Sylk files must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70971
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" /v DifandSylkFiles /t REG_DWORD /d 2 /f

rem V-71025 - ActiveX Installs must be configured for proper restriction
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71025
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" /v excel.exe /t REG_DWORD /d 1 /f

rem V-70973 - Open/Save actions for Excel 2 macrosheets and add-in files must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70973
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" /v XL2Macros /t REG_DWORD /d 2 /f

rem V-71027 - Files in unsafe locations must be opened in Protected View
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71027
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" /v DisableUnsafeLocationsInPV /t REG_DWORD /d 0 /f
rem reg delete HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview /v DisableUnsafeLocationsInPV /f

rem V-71639 - Files on local Intranet UNC must be opened in Protected View
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-71639
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\protectedview" /v DisableIntranetCheck /t REG_DWORD /d 0 /f

rem V-70977 - Open/Save actions for Excel 3 macrosheets and add-in files must be blocked
rem https://www.stigviewer.com/stig/microsoft_excel_2016/2017-09-19/finding/V-70977
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\excel\security\fileblock" /v XL3Macros /t REG_DWORD /d 2 /f
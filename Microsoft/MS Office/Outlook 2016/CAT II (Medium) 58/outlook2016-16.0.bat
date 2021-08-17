rem V-228419 - Disabling of user name and password syntax from being used in URLs must be enforced
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228419
rem The Uniform Resource Locator (URL) standard allows user authentication to be included in URL strings in the form http://username:password@example.com. A malicious user might use this URL syntax to create a hyperlink that appears to open a legitimate website but actually opens a deceptive (spoofed) website. For example, the URL http://www.wingtiptoys.com@example.com appears to open http://www.wingtiptoys.com but actually opens http://example.com. To protect users from such attacks, Internet Explorer usually blocks any URLs using this syntax. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a website). If user names and passwords in URLs are allowed, users could be diverted to dangerous Web pages, which could pose a security risk. 
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228420 - Enabling IE Bind to Object functionality must be present
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228420
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228421 - Saved from URL mark to assure Internet zone processing must be enforced
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228421
reg add "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228422 - Saved from URL mark to assure Internet zone processing must be enforced
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228422
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228423 - Scripted Window Security must be enforced
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228423
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228424 - Add-on Management functionality must be allowed
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228424
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228425 - Links that invoke instances of Internet Explorer from within an Office product must be blocked
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228425
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228426 - File Downloads must be configured for proper restrictions
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228426
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228427 - Protection from zone elevation must be enforced
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228427
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228428 - ActiveX Installs must be configured for proper restriction
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228428
reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228429 - Publishing calendars to Office Online must be prevented
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228429
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228429 - Publishing calendars to Office Online must be prevented
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228429
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal" /v outlook.exe /t REG_DWORD /d 1 /f

rem V-228430 - Publishing to a Web Distributed and Authoring (DAV) server must be prevented
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228430
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal" /v DisableDav /t REG_DWORD /d 1 /f

rem V-228431 - Level of calendar details that a user can publish must be restricted
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228431
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal" /v PublishCalendarDetailsPolicy /t REG_DWORD /d 16384 /f

rem V-228432 - Access restriction settings for published calendars must be configured
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228432
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal" /v RestrictedAccessOnly /t REG_DWORD /d 1 /f

rem V-228433 - Outlook Object Model scripts must be disallowed to run for shared folders
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228433
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v SharedFolderScript /t REG_DWORD /d 0 /f

rem V-228434 - Outlook Object Model scripts must be disallowed to run for public folders
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228434
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v PublicFolderScript /t REG_DWORD /d 0 /f

rem V-228435 - ActiveX One-Off forms must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228435
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v AllowActiveXOneOffForms /t REG_DWORD /d 0 /f

rem V-228436 - The Add-In Trust Level must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228436
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v AddinTrust /t REG_DWORD /d 1 /f

rem V-228437 - The remember password for internet e-mail accounts must be disabled
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228437
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v EnableRememberPwd /t REG_DWORD /d 0 /f

rem V-228438 - Users customizing attachment security settings must be prevented
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228438
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook" /v DisallowAttachmentCustomization /t REG_DWORD /d 1 /f

rem V-228439 - Outlook Security Mode must be configured to use Group Policy settings
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228439
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v AdminSecurityMode /t REG_DWORD /d 3 /f

rem V-228440 - Level 1 file extensions must be blocked and not removed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228440
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v ShowLevel1Attach /t REG_DWORD /d 0 /f

rem V-228441 - Level 1 file extensions must be blocked and not removed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228441
reg delete "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security\FileExtensionsRemoveLevel1" /f

rem V-228442 - Level 2 file extensions must be blocked and not removed
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228442
reg delete "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security\FileExtensionsRemoveLevel2" /f

rem V-228443 - Scripts in One-Off Outlook forms must be disallowed
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228443
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v EnableOneOffFormScripts /t REG_DWORD /d 0 /f

rem V-228444 - Custom Outlook Object Model (OOM) action execution prompts must be configured
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228444
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v PromptOOMCustomAction /t REG_DWORD /d 0 /f

rem V-228445 - Object Model Prompt for programmatic email send behavior must be configured
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228445
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v PromptOOMSend /t REG_DWORD /d 0 /f

rem V-228446 - Object Model Prompt behavior for programmatic address books must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228446
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v PromptOOMAddressBookAccess /t REG_DWORD /d 0 /f

rem V-228447 - Object Model Prompt behavior for programmatic access of user address data must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228447
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v PromptOOMAddressInformationAccess /t REG_DWORD /d 0 /f

rem V-228448 - Object Model Prompt behavior for the SaveAs method must be configured
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228448
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v PromptOOMMeetingTaskRequestResponse /t REG_DWORD /d 0 /f

rem V-228449 - Object Model Prompt behavior for the SaveAs method must be configured
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228449
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v PromptOOMSaveAs /t REG_DWORD /d 0 /f

rem V-228450 - Object Model Prompt behavior for accessing User Property Formula must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228450
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v PromptOOMFormulaAccess /t REG_DWORD /d 0 /f

rem V-228451 - Trusted add-ins behavior for email must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228451
reg delete "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v trustedaddins /f

rem V-228452 - S/Mime interoperability with external clients for message handling must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228452
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v ExternalSMime /t REG_DWORD /d 0 /f

rem V-228453 - Message formats must be set to use SMime
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228453
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v MsgFormats /t REG_DWORD /d 1 /f

rem V-228454 - Run in FIPS compliant mode must be enforced
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228454
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v FIPSMode /t REG_DWORD /d 1 /f

rem V-228455 - Send all signed messages as clear signed messages must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228455
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v ClearSign /t REG_DWORD /d 1 /f

rem V-228456 - Automatic sending s/Mime receipt requests must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228456
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v RespondToReceiptRequests /t REG_DWORD /d 2 /f

rem V-228457 - Retrieving of CRL data must be set for online action
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228457
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v UseCRLChasing /t REG_DWORD /d 1 /f

rem V-228458 - External content and pictures in HTML email must be displayed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228458
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail" /v BlockExtContent /t REG_DWORD /d 1 /f

rem V-228459 - Automatic download content for email in Safe Senders list must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228459
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail" /v UnblockSpecificSenders /t REG_DWORD /d 0 /f

rem V-228460 - Permit download of content from safe zones must be configured
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228460
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail" /v UnblockSafeZone /t REG_DWORD /d 1 /f

rem V-228461 - IE Trusted Zones assumed trusted must be blocked
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228461
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail" /v TrustedZone /t REG_DWORD /d 0 /f

rem V-228462 - Internet with Safe Zones for Picture Download must be disabled
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228462
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail" /v Intranet /t REG_DWORD /d 0 /f

rem V-228463 - Intranet with Safe Zones for automatic picture downloads must be configured
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228463
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\mail" /v Intranet /t REG_DWORD /d 0 /f

rem V-228464 - Always warn on untrusted macros must be enforced
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228464
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\security" /v Level /t REG_DWORD /d 3 /f

rem V-228465 - Hyperlinks in suspected phishing email messages must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228465
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\options\mail" /v JunkMailEnableLinks /t REG_DWORD /d 0 /f

rem V-228466 - RPC encryption between Outlook and Exchange server must be enforced
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228466
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\rpc" /v EnableRPCEncryption /t REG_DWORD /d 1 /f

rem V-228467 - Outlook must be configured to force authentication when connecting to an Exchange server
rem https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228467
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v AuthenticationService /t REG_DWORD /d 16 /f

rem V-228468 - Disabling download full text of articles as HTML must be configured
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228468
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\options\rss" /v EnableFullTextHTML /t REG_DWORD /d 0 /f

rem V-228469 - Automatic download of Internet Calendar appointment attachments must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228469
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\options\webcal" /v EnableAttachments /t REG_DWORD /d 0 /f

rem V-228470 - Internet calendar integration in Outlook must be disabled
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228470
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\webcal" /v Disable /t REG_DWORD /d 1 /f

rem V-228471 - User Entries to Server List must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228471
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\meetings\profile" /v ServerUI /t REG_DWORD /d 2 /f

rem V-228472 - Automatically downloading enclosures on RSS must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228472
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\rss" /v EnableAttachments /t REG_DWORD /d 0 /f

rem V-228473 - Outlook must be configured not to prompt users to choose security settings if default settings fail
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228473
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v ForceDefaultProfile /t REG_DWORD /d 0 /f

rem V-228474 - Outlook minimum encryption key length settings must be set
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228474
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v MinEncKey /t REG_DWORD /d 168 /f

rem V-228475 - Replies or forwards to signed/encrypted messages must be signed/encrypted
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228475
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v NoCheckOnSessionSecurity /t REG_DWORD /d 1 /f

rem V-228476 - Check e-mail addresses against addresses of certificates being used must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228476
reg add "HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security" /v SupressNameChecks /t REG_DWORD /d 1 /f
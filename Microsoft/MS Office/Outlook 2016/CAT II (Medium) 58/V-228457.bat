rem V-228457 - Retrieving of CRL data must be set for online action
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228457
rem This policy setting controls how Outlook retrieves Certificate Revocation Lists to verify the validity of certificates.Certificate revocation lists (CRLs) are lists of digital certificates that have been revoked by their controlling certificate authorities (CAs), typically because the certificates were issued improperly or their associated private keys were compromised. If you enable this policy setting, you can choose from three options to govern how Outlook uses CRLs: - Use system Default. Outlook relies on the CRL download schedule that is configured for the operating system. - When online always retrieve the CRL. This option is the default configuration in Outlook. - Never retrieve the CRL. Outlook will not attempt to download the CRL for a certificate, even if it is online. This option can reduce security. If you disable or do not configure this policy setting, when Outlook handles a certificate that includes a URL from which a CRL can be downloaded, Outlook will retrieve the CRL from the provided URL if Outlook is online. 

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v UseCRLChasing /t REG_DWORD /d 1 /f
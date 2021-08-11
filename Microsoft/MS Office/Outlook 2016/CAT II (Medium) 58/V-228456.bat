rem V-228456 - Automatic sending s/Mime receipt requests must be disallowed
rem https://www.stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228456
rem This policy setting controls how Outlook handles S/MIME receipt requests. If you enable this policy setting, you can choose from four options for handling S/MIME receipt requests in Outlook:- Open message if receipt can't be sent- Don't open message if receipt can't be sent- Always prompt before sending receipt- Never send S/MIME receipts. If you disable or do not configure this policy setting, when users open messages with attached receipt requests, Outlook prompts them to decide whether to send a receipt to the sender with information about the identity of the user who opened the message and the time it was opened. If Outlook cannot send the receipt, the user is still allowed to open the message. 

reg add HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security /v RespondToReceiptRequests /t REG_DWORD /d 2 /f
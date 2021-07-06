<#
.SYNOPSIS
      V-228442 - Level 2 file extensions must be blocked and not removed

.DESCRIPTION
    This policy setting controls which types of attachments (determined by file extension) must be saved to disk before users can open them. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2. If you enable this policy setting, you can specify a list of attachment file types to classify as Level 2, which forces users to actively decide to download the attachment to view it. If you disable or do not configure this policy setting, Outlook does not classify any file type extensions as Level 2. Important: This policy setting only applies if the "Outlook Security Mode" policy setting under "Microsoft Outlook 2016\Security\Security Form Settings" is configured to "Use Outlook Security Group Policy."

.LINK
    https://stigviewer.com/stig/microsoft_outlook_2016/2020-09-25/finding/V-228442
#>

$path = 'HKCU:\Software\Policies\Microsoft\Office\16.0\outlook\security'
$regname = 'FileExtensionsRemoveLevel2'
$regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty $regname

try 
{
    $regvalue
}

catch 
{
    Write-Host Error
}

<#

function fcheckpath
{Test-Path $path}

function fcreate
{
        Write-Host NoPathFound -ForegroundColor Red
        New-Item -Path $path -ItemType Directory
        Write-Host Path Created -ForegroundColor Green
        New-ItemProperty -Path $path -Name $regname -Value 0 -PropertyType DWORD -Force
        Write-Host Registry Created and Set Up -ForegroundColor Green

}

function fcheckreg 
    {
    $regvalue = Get-ItemProperty -Path $path | Select -ExpandProperty $regname
        if ( $regvalue -eq 0 )
        {
            Write-Host "`n$line"
            Write-Host   V-228442 result is $regvalue 
            Write-Host "`n$line"
            Write-Host "This is not a finding" -ForegroundColor Green
            Get-ItemProperty -Path $path
            Write-Host "The Window will close in 5 seconds"
            Start-Sleep -Seconds 5
            }

    else
            {
                Write-Host "`n$line"
                Write-Host   V-228442 result is $regvalue
                Write-Host "`n$line"
                Write-Host "This is a finding" -ForegroundColor Red
                Get-ItemProperty -Path $path
                Write-Host "The Window will close in 5 seconds"
                Start-Sleep -Seconds 5
            } 
    }



if ("Test-Path $path" -like "True")
{
    Write-Host $path
    fcreate
    fcheckreg
}

else {
        Write-Host $path
        fcreate
     }


    
if (fcheckpath -like 'True' )
{fcreate
 fcheckreg}
else{fcheckreg}

#>
# V-220711 - Unused accounts must be disabled or removed from the system after 35 days of inactivity
# https://stigviewer.com/stig/windows_10/2021-03-10/finding/V-220711

([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | 

Where { $_.SchemaClassName -eq 'user' } | 
ForEach {

    $user = ([ADSI]$_.Path)
    $lastLogin = $user.Properties.LastLogin.Value
    $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2

    if ($lastLogin -eq $null) 
        {
        $lastLogin = 'Never'
        }

Write-Host $user.Name $lastLogin $enabled
}

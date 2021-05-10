# V-220708
Get-Volume | Where-Object -Property FilesystemType -eq NTFS
Get-Volume | Where-Object -Property FilesystemType -ne NTFS

# V-220706
winver

# V-220707 - The Windows 10 system must use an anti-virus program
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
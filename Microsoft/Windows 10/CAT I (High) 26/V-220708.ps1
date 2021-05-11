# V-220708

Get-Volume | Where-Object -Property FilesystemType -eq NTFS
Get-Volume | Where-Object -Property FilesystemType -ne NTFS
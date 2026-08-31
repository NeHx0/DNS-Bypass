$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$dir = 'C:\Users\necat\AppData\Local\HackerAI\BlockerKiller-v2'
$ico = Join-Path $dir 'dnsicon.ico'
$exe = Join-Path $dir 'bin\Release\net10.0-windows\BlockerKiller.exe'
$srcIcon = New-Object System.Drawing.Icon($ico, 32, 32)
$srcIcon.ToBitmap().Save((Join-Path $dir 'icon_src_32.png'), [System.Drawing.Imaging.ImageFormat]::Png)
if (Test-Path $exe) {
  $exeIcon = [System.Drawing.Icon]::ExtractAssociatedIcon($exe)
  $exe32 = New-Object System.Drawing.Icon($exeIcon, 32, 32)
  $exe32.ToBitmap().Save((Join-Path $dir 'icon_exe_32.png'), [System.Drawing.Imaging.ImageFormat]::Png)
}
Write-Host 'saved'
Get-Item $ico | Select-Object Length, LastWriteTime
Get-Item $exe | Select-Object Length, LastWriteTime

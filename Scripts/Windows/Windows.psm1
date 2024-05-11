function Edit-Hosts {
    Start-Process notepad c:\windows\system32\drivers\etc\hosts -Verb runas
}

# TODO: No longer used. It can only be used with the old version of Windows 11.
# function global:Update-GUIRegistryValues {
#     $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
#     $key = 'Settings'
#     $org = Get-ItemProperty $path | Select-Object -ExpandProperty $key

#     $new = @() + $org
#     $new[12] = 0x01
#     Set-ItemProperty $path -Name $key -Value $new

#     $path = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
#     New-Item -Path $path -Force
#     Split-Path $path -Parent | Get-ChildItem
#     Set-ItemProperty -Path $path -Name '(Default)' -Value ''

#     Stop-Process -Name explorer -Force
# }
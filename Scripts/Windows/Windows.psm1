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

if (Get-Command -Name docker -ErrorAction SilentlyContinue) {
    # NOTE: This function depends Windows Subsystem for Linux.
    function Optimize-DockerUsage {
        # NOTE: Requires running as Administrator.
        [CmdletBinding()]
        param (
            [Parameter()]
            [switch]
            $ForcePrune
        )
        $ack = Read-Host 'Do you want to optimize docker usage? [y/n]'
        if ($ack -eq 'y') {
            Write-Host 'acknowledged.'
        }
        else {
            Write-Host 'canceled.'
            return
        }
        if ($ForcePrune) {
            if (Get-Process 'com.docker.backend' -ErrorAction SilentlyContinue) {
                Write-Host 'docker backend is running. prune all containers, images, and volumes.'
                docker system prune --all --force
                Write-Host 'pruned.'
            }
            else {
                Write-Host 'docker backend is not running. skip pruning.'
            }
        }
        Write-Host 'shutdown wsl.'
        wsl --shutdown
        Write-Host 'compact vhdx.'
        $vdisk = Resolve-Path "${env:LOCALAPPDATA}\Docker\wsl\data\ext4.vhdx"
        $tmp = "${env:Temp}/diskpart.txt"
        @"
select vdisk file="$vdisk"
compact vdisk
"@ | Set-Content -Path $tmp
        diskpart /s $tmp > ./log.txt
        Get-Content ./log.txt | Write-Host
        Remove-Item $tmp, ./log.txt
    }
}
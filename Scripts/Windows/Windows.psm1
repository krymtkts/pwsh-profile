if ((Get-Command -Name docker -ErrorAction SilentlyContinue) -and (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
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
        Write-Host 'cooling down in 5 seconds...'
        Start-Sleep -Seconds 5
        Write-Host 'compact vhdx.'

        Get-ChildItem "${env:LOCALAPPDATA}\Docker\wsl\*\*.vhdx" | ForEach-Object {
            $vdisk = Resolve-Path $_
            if (-not $vdisk) {
                Write-Host "failed to resolve path for $_."
                return
            }
            Write-Host "compact $vdisk."
            $tmp = "${env:Temp}/diskpart.txt"
            @"
select vdisk file="$vdisk"
compact vdisk
"@ | Set-Content -Path $tmp
            diskpart /s $tmp > ./log.txt
            Get-Content ./log.txt | Write-Host
            Remove-Item $tmp, ./log.txt
            Write-Host "compacted $vdisk."
        }
    }
}
<#
.SYNOPSIS
    This script provides argument completions for various commands.
    If you want to add functions that are not related to completions, move specific complete function to a specific module.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are used in script blocks and argument completers')]
param ()

function Install-WindowsTerminalCanary {
    Invoke-WebRequest 'https://aka.ms/terminal-canary-installer' -OutFile 'Microsoft.WindowsTerminalCanary.appinstaller'
    Start-Process 'Microsoft.WindowsTerminalCanary.appinstaller'
    # TODO; check if this works as intended.
    # try {
    #     Add-AppxPackage -AppInstallerFile $installer
    # }
    # finally {
    #     Remove-Item $installer -Force -ErrorAction SilentlyContinue
    # }
}

function Install-OhMyPoshTheme {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ThemePath = '~/.oh-my-posh.omp.yaml'
    )
    $params = @{
        Uri = 'https://gist.githubusercontent.com/krymtkts/d320ff5ec30fa47b138c2df018f95423/raw/58450313f773df801225f6e4053b289d67de4cb1/.oh-my-posh.omp.yaml'
        OutFile = $ThemePath
    }
    Invoke-WebRequest @params
}

if ((Get-Command -Name docker -ErrorAction SilentlyContinue) -and (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    function Set-WindowsClassicContextMenu {
        $path = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
        New-Item -Path $path -Force
        Split-Path $path -Parent | Get-ChildItem
        Set-ItemProperty -Path $path -Name '(Default)' -Value ''
        Get-ItemProperty $path

        Stop-Process -Name explorer -Force
    }

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

# NOTE: Define FancyZonesCli and FileLocksmithCLI aliases if PowerToys is installed.
if (Test-Path "${env:ProgramFiles}/PowerToys") {
    $fancyZonesCli = "${env:ProgramFiles}/PowerToys/FancyZonesCli.exe"
    $fileLocksmithCLI = "${env:ProgramFiles}/PowerToys/FileLocksmithCLI.exe"

    # NOTE: Define FancyZonesCli function ins and its argument completer.
    if (Test-Path $fancyZonesCli) {
        function FancyZonesCli {
            & $fancyZonesCli @Args
        }
        function global:Get-FancyZonesCliOptions {
            & $fancyZonesCli --help | ForEach-Object -Begin {
                $options = @()
                $subcommands = @()
                $current = ''
            } -Process {
                $line = $_
                if (-not $line) {
                    $current = ''
                }
                elseif ($_ -match '^Options:$') {
                    # TODO: currently Options section has no entries.
                    $current = 'Options'
                    '--help', '--version' | ForEach-Object {
                        $options += [PSCustomObject]@{Option = $_; Description = $_ }
                    }
                }
                elseif ($_ -match '^Commands:$') {
                    $current = 'Commands'
                }
                elseif ($_ -match '^Examples:$') {
                    $current = 'Examples'
                }
                switch ($current) {
                    'Options' {
                    }
                    'Commands' {
                        if ($line -match '^\s{2}(?<cmdpart>.+?),\s*(?<alias>\S+)\s+(?<desc>.+)$') {
                            $primary = ($matches.cmdpart.Trim() -split '\s+')[0]   # set-hotkey / set-layout など
                            $primary, $matches.alias.Trim() | Where-Object Length | ForEach-Object {
                                $subcommands += [PSCustomObject]@{
                                    Option = $_
                                    Description = $matches.desc.Trim()
                                }
                            }
                        }
                        elseif ($line -match '^\s{2}(?<cmdpart>.+?)\s{2,}(?<desc>.+)$') {
                            $primary = ($matches.cmdpart.Trim() -split '\s+')[0]
                            if ($primary) {
                                $subcommands += [PSCustomObject]@{
                                    Option = $primary
                                    Description = $matches.desc.Trim()
                                }
                            }
                        }
                    }
                    'Examples' {
                    }
                }
            } -End {
                $options
                $subcommands
            }
        }
        Register-ArgumentCompleter -Native -CommandName FancyZonesCli -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)

            Add-Content ./debug.txt "$wordToComplete, $commandAst, $cursorPosition"
            Add-Content ./debug.txt "$wordToComplete* -> $(Get-FancyZonesCliOptions | Where-Object -Property Option -Like "$wordToComplete*"  | Measure-Object | ForEach-Object Count)"
            Get-FancyZonesCliOptions | Where-Object -Property Option -Like "$wordToComplete*" | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_.Option, $_.Option, 'ParameterValue', $_.Description)
            }
        }
    }
    # NOTE: Define FileLocksmithCli function and its argument completer.
    if (Test-Path $fileLocksmithCLI) {
        function FileLocksmithCli {
            & $fileLocksmithCLI @Args
        }
        function global:Get-FileLocksmithCliOptions {
            & $fileLocksmithCLI --help | ForEach-Object -Begin {
                $options = @()
                $beginOptions = $false
            } -Process {
                if ($_ -match '^Options:$') {
                    $beginOptions = $true
                }
                else {
                    if ($beginOptions) {
                        if ($_ -match '^\s{2}(--\S+)\s+(.*)$') {
                            $option = $matches[1]
                            $description = $matches[2].Trim()
                            $options += [PSCustomObject]@{
                                Option = $option
                                Description = $description
                            }
                        }
                    }
                }
            } -End {
                $options
            }
        }
        Register-ArgumentCompleter -Native -CommandName FileLocksmithCli -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)

            Get-FileLocksmithCliOptions | Where-Object -Property Option -Like "$wordToComplete*" | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_.Option, $_.Option, 'ParameterValue', $_.Description)
            }
        }
    }
}

if (Get-Command Get-WinGetPackage -ErrorAction SilentlyContinue) {
    @(
        'Microsoft.VisualStudioCode.Insiders'
        'Microsoft.OpenSSH.Preview'
        'Microsoft.PowerShell.Preview'
        'Microsoft.PowerToys'
        'WinsiderSS.SystemInformer.Canary'
    ) | ForEach-Object {
        $pkg = Get-WinGetPackage -Id $_
        if ($pkg -and $pkg.IsUpdateAvailable) {
            # NOTE: Avoid errors when InstalledVersion returns multiple values.
            $installedVersion = [version]($pkg.InstalledVersion | Get-Unique | Sort-Object -Descending | Select-Object -First 1)
            Write-Warning "💡 Newer '${_}' is available. $($pkg.AvailableVersions | Where-Object {
                [version]$_ -gt $installedVersion
            } | Sort-Object -Descending | Select-Object -First 1)"
        }
    }
}


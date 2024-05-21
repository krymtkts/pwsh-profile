function local:Start {
    $global:profileStart = Get-Date
    $totalSeconds = {
        $profileEnd = Get-Date
        $loadTime = $profileEnd - $profileStart
        Remove-Variable profileStart -Scope Global
        $loadTime.TotalSeconds
    }
    return $totalSeconds
}
$totalSeconds = local:Start

function local:Complete {
    $Horns = [char]::ConvertFromUtf32(0x1f918)
    Write-Host "$Horns pwsh $($PSVersionTable.PSVersion.ToString()) is ready $Horns User profile loaded in $(&$totalSeconds) seconds"
}

Get-ChildItem "$($PROFILE | Split-Path -Parent)/Scripts" -Recurse -File -Filter *.psm1 | Import-Module -Force

function global:Update-ProfileScripts {
    @(
        'Autocomplete/Autocomplete.psm1'
        'AWS/AWS.psm1'
        'Functions/Functions.psm1'
        'Get-Hash/Get-Hash.psm1'
        'Git/Git.psm1'
        'Go/Go.psm1'
        'Mod/Mod.psm1'
        'Nodejs/Nodejs.psm1'
        'OpenAI/OpenAI.psm1'
        'Pocof/Pocof.psm1'
        'Psake/Psake.psm1'
        'PSResource/PSResource.psm1'
        'Python/Python.psm1'
        'StandardNotes/StandardNotes.psm1'
        'Strings/Strings.psm1'
        'Windows/Windows.psm1'
    ) | ForEach-Object {
        $scriptPath = "${ProfileHome}/Scripts/${_}"
        if (-not (Split-Path $scriptPath -Parent | Test-Path)) {
            New-Item -ItemType Directory -Path (Split-Path $scriptPath -Parent) -Force
        }
        $params = @{
            Uri = "${baseUrl}/Scripts/${_}"
            OutFile = "${ProfileHome}/Scripts/${_}"
        }
        Invoke-WebRequest @params | Out-Null
    }
}

function global:Update-Profile {
    $ProfileHome = ($PROFILE | Split-Path -Parent)
    $ProfilePath = "${ProfileHome}/Microsoft.PowerShell_profile.ps1"
    $baseUrl = 'https://raw.githubusercontent.com/krymtkts/pwsh-profile/main/'
    $params = @{
        Uri = "${baseUrl}/Microsoft.PowerShell_profile.ps1"
        OutFile = $ProfilePath
    }
    Invoke-WebRequest @params | Out-Null

    if (-not (Test-Path "${ProfileHome}/Microsoft.VSCode_profile.ps1")) {
        New-Item -ItemType HardLink -Path $ProfileHome -Name 'Microsoft.VSCode_profile.ps1' -Value $ProfilePath
    }
    # TODO: load the profile to prepare new psm1 files.
    . $ProfilePath

    Update-ProfileScripts

    # TODO: load the profile again to apply new psm1 files.
    . $ProfilePath
}

if (Get-Command -Name docker -ErrorAction SilentlyContinue) {
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

# NOTE: setting section of Microsoft.PowerShell_profile.ps1

function Update-Packages {
    @(
        'Update-InstalledModules'
        'Update-AWSModules'
        'Update-PipModules'
        'Update-NodeModules'
        'Update-GoModules'
    ) | ForEach-Object {
        if (Get-Command -Name $_ -ErrorAction SilentlyContinue) {
            &$_
        }
    }
}


# change display language for gpg.
$env:LANG = 'en'
# enable Python UTF-8 Mode.
$env:PYTHONUTF8 = 1
[System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
[System.Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# TLS versions.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# set PSReadLine options.
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadLineOption -BellStyle Visual

# Set aliases.
Set-Alias ll ls -Option ReadOnly -Force -Scope Global

if (-not (Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
    Write-Error @'
to install ssh-agent service, run below command.

`choco install openssh -params '"/SSHAgentFeature"' -y`

don't use `install-sshd.ps1` to prevent from installing sshd service.
'@
}

# Set default parameter values.
if (Get-Command -Name Get-PSDefaultParameterValuesForPocof -ErrorAction SilentlyContinue) {
    (Get-PSDefaultParameterValuesForPocof).GetEnumerator() | ForEach-Object {
        $PSDefaultParameterValues[$_.Key] = $_.Value
    }
}

# prepare for Chocolatey.
$local:ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($local:ChocolateyProfile)) {
    # NOTE: currently, autocomplete for Chocolatey is not work.
    # https://github.com/chocolatey/choco/issues/3364
    Import-Module "$local:ChocolateyProfile"
}

if (Test-Path "$env:ProgramFiles\PowerToys") {
    # NOTE: PowerToys CommandNotFound module requires PSFeedbackProvider and PSCommandNotFoundSuggestion.
    ## Enable-ExperimentalFeature -Name PSFeedbackProvider
    ## Enable-ExperimentalFeature -Name PSCommandNotFoundSuggestion
    #34de4b3d-13a8-4540-b76d-b9e8d3851756 PowerToys CommandNotFound module
    Import-Module "$env:ProgramFiles\PowerToys\WinGetCommandNotFound.psd1"
    #34de4b3d-13a8-4540-b76d-b9e8d3851756
}

# set a prompt theme.
if (Get-Command -Name oh-my-posh -ErrorAction SilentlyContinue) {
    oh-my-posh init pwsh --config ~/.oh-my-posh.omp.yaml | Invoke-Expression
}

# NOTE: end of Microsoft.PowerShell_profile.ps1
local:Complete

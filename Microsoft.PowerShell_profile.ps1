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

$ProfileHome = ($PROFILE | Split-Path -Parent)
Get-ChildItem "${ProfileHome}/Scripts" -Recurse -File -Filter *.psm1 | Import-Module -Force

function Update-ProfileScripts {
    param (
        [Parameter()]
        [string]
        $ProfileHome = ($PROFILE | Split-Path -Parent) # NOTE: for backward compatibility.
    )
    @(
        'AWS'
        'Autocomplete'
        'Dotnet'
        'Functions'
        'Get-Hash'
        'Git'
        'Go'
        'Mod'
        'Nodejs'
        'PSResource'
        'Pocof'
        'Psake'
        'Python'
        'StandardNotes'
        'Strings'
        'Windows'
    ) | ForEach-Object {
        $modulePath = "${_}/${_}.psm1"
        $scriptPath = "${ProfileHome}/Scripts/${modulePath}"
        if (-not (Split-Path $scriptPath -Parent | Test-Path)) {
            New-Item -ItemType Directory -Path (Split-Path $scriptPath -Parent) -Force | Out-Null
            Write-Host "Created directory: $(Split-Path $scriptPath -Parent)"
        }
        $params = @{
            Uri = "${baseUrl}/Scripts/${modulePath}?$(Get-Random)" # NOTE: prevent caching
            Headers = @{
                'Cache-Control' = 'no-cache'
            }
            OutFile = $scriptPath
        }
        Invoke-WebRequest @params | Out-Null
    }
}

function Update-Profile {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        # NOTE: Recalculate $ProfileHome each time so this function also works correctly after Update-Profile reloads the profile.
        $ProfileHome = ($PROFILE | Split-Path -Parent)
        $ProfilePath = "${ProfileHome}/Microsoft.PowerShell_profile.ps1"
        $baseUrl = 'https://raw.githubusercontent.com/krymtkts/pwsh-profile/main'
        $params = @{
            Uri = "${baseUrl}/Microsoft.PowerShell_profile.ps1?$(Get-Random)" # NOTE: prevent caching
            Headers = @{
                'Cache-Control' = 'no-cache'
            }
            OutFile = $ProfilePath
        }
        Invoke-WebRequest @params | Out-Null

        if (-not (Test-Path "${ProfileHome}/Microsoft.VSCode_profile.ps1")) {
            New-Item -ItemType HardLink -Path $ProfileHome -Name 'Microsoft.VSCode_profile.ps1' -Value $ProfilePath
        }
        # TODO: load the profile to prepare new psm1 files.
        . $ProfilePath

        Update-ProfileScripts -ProfileHome $ProfileHome

        # TODO: load the profile again to apply new psm1 files.
        . $ProfilePath
    }
    catch {
        throw $_
    }
    finally {
        $ErrorActionPreference = $old
    }
}

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
$PSReadLineParams = @{
    PredictionSource = 'HistoryAndPlugin'
    PredictionViewStyle = 'ListView'
    BellStyle = 'Visual'
    WordDelimiters = Get-PSReadLineOption | Select-Object -ExpandProperty WordDelimiters | ForEach-Object {
        (($_ + '_`').GetEnumerator() | Sort-Object | Get-Unique) -join ''
    }
    Colors = @{
        Comment = "`e[39;2;3m"
        Keyword = "`e[34m"
        Number = "`e[35m"
        Operator = "`e[32m"
        Variable = "`e[34m"
        Type = "`e[95m"
    }
}
Set-PSReadLineOption @PSReadLineParams

# Set aliases.
Set-Alias ll ls -Option ReadOnly -Force -Scope Global

if (-not (Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
    Write-Error @'
to install ssh-agent service, run below command.

`winget install --id Microsoft.OpenSSH.Preview --scope machine --override ADDLOCAL=Client`

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
    #f45873b3-b655-43a6-b217-97c00aa0db58 PowerToys CommandNotFound module
    Import-Module -Name Microsoft.WinGet.CommandNotFound
    #f45873b3-b655-43a6-b217-97c00aa0db58
}

# set a prompt theme.
if (Get-Command -Name oh-my-posh -ErrorAction SilentlyContinue) {
    oh-my-posh init pwsh --config ~/.oh-my-posh.omp.yaml | Invoke-Expression
}

# NOTE: to load help correctly.
if (-not (Get-Module -Name SnippetPredictor -ErrorAction SilentlyContinue)) {
    Import-Module SnippetPredictor
}

# NOTE: end of Microsoft.PowerShell_profile.ps1
local:Complete

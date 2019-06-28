# Ensure that Get-ChildItemColor is loaded
Import-Module Get-ChildItemColor

# Prepare for PowerShell
Import-Module -Name PowerShellGet, PSScriptAnalyzer, Pester, psake

# Prepare for Maven
Import-Module -Name MavenAutoCompletion

# Prepare for poco
Import-Module -Name poco

function Set-SelectedLocation {
    param(
        [ValidateSet("Add", "Move", "Edit")]$Mode = "Move",
        [string]$Location
    )
    switch ($Mode)
    {
        "Add" {
            if ($Location) {
                Write-Output "$Location" | Out-File -Append -Encoding UTF8 "~/.poco-cd"
                break
            }
        }
        "Move" {
            Get-Content -Path "~/.poco-cd" | Select-Poco -CaseSensitive | Select-Object -First 1 | Set-Location
            break
        }
        "Edit" {
            break
        }
    }
}
Set-Alias pcd Set-SelectedLocation -Option AllScope

function Set-SelectedRepository {
    ghq list | Select-Poco | Select-Object -First 1 | %{Set-Location "$(ghq root)/$_"}
}
Set-Alias gcd Set-SelectedRepository -Option AllScope

function Show-Paths() {
    ($Env:Path).split(';') | poco
}

function Show-ReadLineHistory() {
    Get-Content -Path (Get-PSReadlineOption).HistorySavePath | poco
}
Set-Alias phistory Show-ReadLineHistory -Option AllScope

# Prepare for Github
Import-Module -Name PowerShellForGitHub

# Prepare for Google Cloud
if (Get-Module -Name GoogleCloud) {
    Import-Module -Name GoogleCloud
}

# Set l and ls alias to use the new Get-ChildItemColor cmdlets
Set-Alias ls Get-ChildItemColorFormatWide -Option AllScope
Set-Alias ll Get-ChildItemColor -Option AllScope

# Helper function to change directory to my development workspace
# Change c:\ws to your usual workspace and everytime you type
# in cws from PowerShell it will take you directly there.
# function cws { Set-Location c:\workspace }

# Helper function to set location to the User Profile directory
function cuserprofile { Set-Location ~ }
Set-Alias ~ cuserprofile -Option AllScope

# Helper function to edit hosts file.
function Edit-Hosts {
    Start-Process notepad c:\windows\system32\drivers\etc\hosts -verb runas
}

# Helper function to execute choco upgrade.
function Update-ChocoPackages {
    choco upgrade chocolatey -y
    # finish to install faster than other apps.
    choco upgrade GoogleChrome vscode -y
    choco upgrade all -y
}

function New-EmptyFIle([parameter(mandatory)][string]$Name) {
    New-Item -Name $Name -ItemType File
}
Set-Alias touch New-EmptyFile -Option AllScope

function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    New-Item -ItemType Directory -Path (Join-Path $parent $name)
}
Set-Alias tmpdir New-TemporaryDirectory -Option AllScope

# Helper function to show Unicode character
function global:U
{
    param
    (
        [int] $Code
    )

    if ((0 -le $Code) -and ($Code -le 0xFFFF))
    {
        return [char] $Code
    }

    if ((0x10000 -le $Code) -and ($Code -le 0x10FFFF))
    {
        return [char]::ConvertFromUtf32($Code)
    }

    throw "Invalid character code $Code"
}

# Start Open SSH Agent if not already
# Need this if you are using github as your remote git repository
if (! (Get-Process -Name 'ssh-agent')) {
    Start-Service ssh-agent
}

# Ensure oh-my-posh is loaded
Import-Module -Name oh-my-posh

# Default the prompt to agnoster oh-my-posh theme
Set-Theme agnoster

# modify symbols. thunder -> muscle
$Muscle = [char]::ConvertFromUtf32(0x1f4aa)
$ThemeSettings.PromptSymbols.ElevatedSymbol = $Muscle
# modify symbols. triangle -> sidefire
$Fire = [char]::ConvertFromUtf32(0xe0c0)
$ThemeSettings.PromptSymbols.SegmentForwardSymbol = $Fire
$ThemeSettings.PromptSymbols.SegmentSeparatorForwardSymbol = $Fire
$BackFire = [char]::ConvertFromUtf32(0xe0c2)
$ThemeSettings.PromptSymbols.SegmentBackwardSymbol = $BackFire
$ThemeSettings.PromptSymbols.SegmentSeparatorBackwardSymbol = $BackFire

$Horns = [char]::ConvertFromUtf32(0x1f918)
Write-Host "$Horns posh $($PSVersionTable.PSVersion.ToString()) is ready $Horns"
# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}

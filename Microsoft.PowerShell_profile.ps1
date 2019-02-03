# Ensure that Get-ChildItemColor is loaded
Import-Module Get-ChildItemColor

# Prepare for PowerShell Gallary
Import-Module -Name PowerShellGet
Import-Module -Name PSScriptAnalyzer
Import-Module -Name Pester

# Set l and ls alias to use the new Get-ChildItemColor cmdlets
Set-Alias l Get-ChildItemColor -Option AllScope
Set-Alias ls Get-ChildItemColorFormatWide -Option AllScope

# Helper function to set location to the User Profile directory
function cuserprofile { Set-Location ~ }
Set-Alias ~ cuserprofile -Option AllScope

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

# modify symbols. ⚡->💪
$Muscle = [char]::ConvertFromUtf32(0x1f4aa)
$ThemeSettings.PromptSymbols.ElevatedSymbol = $Muscle
# modify symbols. ->
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
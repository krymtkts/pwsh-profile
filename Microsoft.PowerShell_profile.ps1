$completions = @(
    # Prepare for Maven
    'MavenAutoCompletion',
    # Prepare for Docker
    'DockerCompletion', 'DockerComposeCompletion', 'DockerMachineCompletion'
)
$names = @(
    # Prepare basic utilities
    'PSReadLine', 'ClipboardText', 'Get-ChildItemColor',
    'posh-git', 'oh-my-posh', 'PowerShellGet', 'poco', 'Get-GzipContent',
    # Prepare for PowerShell
    'PowerShellGet', 'PSScriptAnalyzer', 'Pester', 'psake',
    # Prepare for GitHub
    'PowerShellForGitHub'
    # Prepare for AWS https://dev.classmethod.jp/server-side/problem-about-awspowershell-netcore-not-autoloaded/
    # 'AWSPowerShell.NetCore'
) + $completions

Function Install-NonExistsModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True,
            ValueFromPipeline = $True)]
        [string[]]$Name
    )

    begin {
        $modules = Get-InstalledModule
    }

    process {
        foreach ($n in $Name) {
            Write-Debug $n
            if (!($modules | Where-Object -Property Name -eq $n)) {
                Install-Module -Name $n -AllowPrerelease -AllowClobber -Scope AllUsers
            }
            $n
        }
    }
}

$names | Install-NonExistsModule | Out-Null
Import-Module -Name $completions

function gitlog { git log --graph --all --decorate --abbrev-commit --branches --oneline }

function Set-SelectedLocation {
    param(
        [ValidateSet("Add", "Move", "Open")]$Mode = "Move",
        [string]$Location,
        [switch]$Here
    )
    switch ($Mode) {
        "Add" {
            if ($Location) {
                Write-Output "$Location" | Out-File -Append -Encoding UTF8 "~/.poco-cd"
                break
            }
            elseif ($Here) {
                Write-Output "$(Get-Location)" | Out-File -Append -Encoding UTF8 "~/.poco-cd"
            }
        }
        "Move" {
            Get-Content -Path "~/.poco-cd" | Select-Poco -CaseSensitive | Select-Object -First 1 | Set-Location
            break
        }
        "Open" {
            Get-Content -Path "~/.poco-cd" | Select-Poco -CaseSensitive | Select-Object -First 1 | Invoke-Item
            break
        }
    }
}
Set-Alias pcd Set-SelectedLocation -Option AllScope
function Invoke-SelectedLocation() {
    Set-SelectedLocation -Mode Open
}
Set-Alias pii Invoke-SelectedLocation -Option AllScope


function Open-VSCodeWorkspace {
    param(
        [ValidateSet("Add", "Open")]$Mode = "Open",
        # Specifies a path to one or more locations.
        [Parameter(
            Position = 0,
            ParameterSetName = "Path",
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Path
    )
    $file = "~/.code-ws"
    switch ($Mode) {
        "Add" {
            if ($Path -and (Test-Path($Path))) {
                (Resolve-Path $Path).Path | Out-File -Append -Encoding UTF8 $file
                break
            }
            else {
                Write-Host 'no .code-workspace found.'
            }
        }
        "Open" {
            $ws = Get-Content -Path $file | Select-Poco -CaseSensitive | Select-Object -First 1
            if ($ws) {
                code $ws
            }
            break
        }
    }
}
Set-Alias codeof Open-VSCodeWorkspace -Option AllScope


function Set-SelectedRepository {
    ghq list | Select-Poco | Select-Object -First 1 | % { Set-Location "$(ghq root)/$_" }
}
Set-Alias gcd Set-SelectedRepository -Option AllScope

function Show-Paths() {
    ($Env:Path).split(';') | poco
}

function Show-ReadLineHistory() {
    Get-Content -Path (Get-PSReadlineOption).HistorySavePath | Select-Object -Unique | Select-Poco -CaseSensitive
}
Set-Alias pghy Show-ReadLineHistory -Option AllScope

function Invoke-ReadLineHistory() {
    Show-ReadLineHistory | Select-Object -First 1 | Invoke-Expression
}
Set-Alias pihy Invoke-ReadLineHistory -Option AllScope

function Start-VBoxMachine() {
    vboxmanage list vms | Select-Poco -CaseSensitive | Out-String -Stream | Select-String -Pattern '\{(.+)\}' | ForEach-Object { vboxmanage startvm ($_.Matches[0].Groups['1'].Value) --type headless }
}

function Stop-VBoxMachine() {
    vboxmanage list runningvms | Select-Poco -CaseSensitive | Out-String -Stream | Select-String -Pattern '\{(.+)\}' | ForEach-Object { vboxmanage controlvm ($_.Matches[0].Groups['1'].Value) poweroff }
}

function Get-RunningVBoxMachines() {
    vboxmanage list runningvms
}

# Prepare for Github
Import-Module -Name PowerShellForGitHub

# Prepare for Google Cloud
if (Get-Module -Name GoogleCloud) {
    Import-Module -Name GoogleCloud
}

# # Set l and ls alias to use the new Get-ChildItemColor cmdlets
# Set-Alias ls Get-ChildItemColorFormatWide -Option AllScope
# Set-Alias ll Get-ChildItemColor -Option AllScope

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

function Update-PipModules {
    python -m pip install --upgrade pip
    pip list --outdated | ForEach-Object { [string]::Join(',', $_ -split "\s+") } | `
        ConvertFrom-Csv -Header Package, Version, Latest, Type | `
        Select-Object -Property Package -Skip 2 | `
        ForEach-Object { pip install -U $_.Package }
}
# Helper function to execute choco upgrade.

function Update-Packages {
    # Update PowerShell modules.
    Get-InstalledModule | Update-Module -AllowPrerelease

    # Update Pip modules.
    Update-PipModules

    choco upgrade chocolatey -y
    # finish to install faster than other apps.
    choco upgrade GoogleChrome vscode microsoft-windows-terminal -y
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
function global:U {
    param
    (
        [int] $Code
    )

    if ((0 -le $Code) -and ($Code -le 0xFFFF)) {
        return [char] $Code
    }

    if ((0x10000 -le $Code) -and ($Code -le 0x10FFFF)) {
        return [char]::ConvertFromUtf32($Code)
    }

    throw "Invalid character code $Code"
}

# install ssh-agent service if not exists.
# it will happend after updating Windows OpenSSH.
if (! ($SshAgent = (Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue))) {
    install-sshd.ps1
    Set-Service -Name "ssh-agent" -StartupType Automatic
    Start-Service ssh-agent
}
elseif ($SshAgent.StartType -eq 'Disabled') {
    Set-Service -Name "ssh-agent" -StartupType Automatic
    Start-Service ssh-agent
}
else {
    Start-Service ssh-agent
}

# Default the prompt to agnoster oh-my-posh theme
Set-Theme krymtkts

$Horns = [char]::ConvertFromUtf32(0x1f918)
Write-Host "$Horns posh $($PSVersionTable.PSVersion.ToString()) is ready $Horns"
# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

if (Test-Path("$PSScriptRoot\CustomScript.psm1")) {
    # Import environment specific script from CustomScript.psm1.
    Import-Module "$PSScriptRoot\CustomScript.psm1"
}

function find {
    [CmdletBinding()]
    param(
        [string]$path = '.',
        [Parameter(Mandatory = $True,
            ValueFromPipeline = $True)]
        [string[]]$name,
        [switch]$delete
    )

    begin {
    }

    process {
        foreach ($n in $Name) {
            if ($delete) {
                Get-ChildItem -Recurse -Path $path | Where-Object -Property Name -like $n | Remove-Item
            }
            else {
                Get-ChildItem -Recurse -Path $path | Where-Object -Property Name -like $n
            }
        }
    }

    end {
    }
}

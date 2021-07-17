$completions = @(
    'Terminal-Icons',
    # Prepare for Maven
    'MavenAutoCompletion',
    # Prepare for Docker
    'DockerCompletion', 'DockerComposeCompletion', 'DockerMachineCompletion'
)
$names = @(
    # Prepare basic utilities
    'PSReadLine', 'ClipboardText',
    'posh-git', 'oh-my-posh', 'PowerShellGet', 'poco', 'Get-GzipContent',
    'powershell-yaml',
    # Prepare for PowerShell
    'PowerShellGet', 'PSScriptAnalyzer', 'Pester', 'psake', 'PSProfiler',
    # Prepare for GitHub
    'PowerShellForGitHub',
    # Prepare for AWS
    'AWS.Tools.Installer'
) + $completions
$awsServices = @(
    'CertificateManager',
    'CloudFormation',
    'CloudWatchLogs',
    'DynamoDBv2',
    'EC2',
    'ECR',
    'ECS',
    'ElasticLoadBalancingV2',
    'EventBridge',
    'IdentityManagement',
    'Lambda',
    'S3',
    'SecretsManager',
    'SecurityToken',
    'StepFunctions'
)

function Install-NonExistsModule {
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

function Install-AWSModules {
    Install-AWSToolsModule -Name $awsServices -Scope AllUsers
}

function Install-Modules {
    $names | Install-NonExistsModule | Out-Null
    Install-AWSModules | Out-Null
}

Import-Module -Name $completions

Set-Alias ll ls -Option AllScope

Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadLineOption -BellStyle Visual

function Remove-GitGoneBranches {
    [CmdletBinding()]
    param (
        [switch]$Force
    )
    $deleteFlag = '--delete'
    if ($Force) {
        $deleteFlag = '-D'
    }
    git branch --format "%(refname:short)=%(upstream:track)"  |  Where-Object -FilterScript { $_ -like '*`[gone`]*' } | ConvertFrom-StringData | Select-Object  -ExpandProperty Keys | % { git branch $deleteFlag $_ }
}

function Get-GitGraph {
    git log --graph --all --decorate --abbrev-commit --branches --oneline
}

Set-Alias gitgraph Get-GitGraph -Option AllScope

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
            $ws = Get-Content -Path $file | Where-Object { !$_.StartsWith('#') } | Select-Poco -CaseSensitive | Select-Object -First 1
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

function Update-InstalledModules {
    Get-InstalledModule | Where-Object -Property Repository -eq 'PSGallery' | Update-Module -AllowPrerelease -Scope AllUsers
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
    Update-InstalledModules
    Update-AWSToolsModule -Scope AllUsers
    Update-PipModules
    # choco upgrade chocolatey -y
    # # finish to install faster than other apps.
    # choco upgrade GoogleChrome vscode microsoft-windows-terminal -y
    # choco upgrade all -y
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
function U {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [int[]] $Code
    )
    process {
        foreach ($c in $Code) {
            if ((0 -le $c) -and ($c -le 0xFFFF)) {
                [char] $c
            }
            elseif ((0x10000 -le $c) -and ($c -le 0x10FFFF)) {
                [char]::ConvertFromUtf32($c)
            }
            else {
                throw "Invalid character code $c"
            }
        }
    }
}

function UC {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$s
    )
    process {
        foreach ($c in $s) {
            [Convert]::ToInt32($c -as [char]).ToString("x")
        }
    }
}

function Convert-0xTo10 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$0x
    )
    process {
        foreach ($c in $0x) {
            [Convert]::ToInt32($c, 16)
        }
    }
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

function New-Password {
    [CmdletBinding()]
    param (
        # Length is password length.
        [Parameter(Mandatory = $True)]
        [int]
        $Length
    )

    begin {

    }

    process {
        $uppers = "ABCDEFGHJKLMNPQRSTUVWXYZ".ToCharArray()
        $lowers = "abcdefghijkmnopqrstuvwxyz".ToCharArray()
        $digits = "23456789".ToCharArray()
        $symbols = "_-+=@$%".ToCharArray()

        $chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789_-+=@$%".ToCharArray()

        do {
            $pwdChars = "".ToCharArray()
            $goodPassword = $false
            $hasDigit = $false
            $hasSymbol = $false
            $pwdChars += (Get-Random -InputObject $uppers -Count 1)
            for ($i = 1; $i -lt $length; $i++) {
                $char = Get-Random -InputObject $chars -Count 1
                if ($digits -contains $char) { $hasDigit = $true }
                if ($symbols -contains $char) { $hasSymbol = $true }
                $pwdChars += $char
            }
            $pwdChars += (Get-Random -InputObject $lowers -Count 1)
            $password = $pwdChars -join ""
            $goodPassword = $hasDigit -and $hasSymbol
        } until ($goodPassword)
    }

    end {
        $password
    }
}

# This idea was inspired by  https://github.com/aws/aws-cli/issues/5309#issuecomment-693941619
$awsCompleter = Get-Command -Name aws_completer -ErrorAction SilentlyContinue
if ($awsCompleter) {
    if ($awsCompleter.Name -like '*.py' ) {
        $f = { python $awsCompleter.Source }
    }
    else {
        $f = { & $awsCompleter.Name }
    }
    Register-ArgumentCompleter -Native -CommandName aws -ScriptBlock {
        param($commandName, $wordToComplete, $cursorPosition)
        $Env:COMP_LINE = $wordToComplete
        $Env:COMP_POINT = $cursorPosition
        & $f | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}

function Remove-GitGoneBranches {
    git branch --format '%(refname:short)=%(upstream:track)' | Where-Object -FilterScript { $_ -like '*`[gone`]*' } | ConvertFrom-StringData | Select-Object -ExpandProperty Keys | ForEach-Object { git branch --delete $_ }
}

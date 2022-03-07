$completions = @(
    'Terminal-Icons'
    # Prepare for Maven
    'MavenAutoCompletion'
    # Prepare for Docker
    'DockerCompletion', 'DockerComposeCompletion', 'DockerMachineCompletion'
    'posh-git'
)
$names = @(
    # Prepare basic utilities
    'PSReadLine', 'ClipboardText'
    'oh-my-posh', 'PowerShellGet', 'poco', 'Get-GzipContent'
    'powershell-yaml'
    # Prepare for PowerShell
    'PowerShellGet', 'PSScriptAnalyzer', 'Pester', 'psake', 'PSProfiler'
    # Prepare for GitHub
    'PowerShellForGitHub'
    # Prepare for AWS
    'AWS.Tools.Installer'
) + $completions
$awsServices = @(
    'CertificateManager'
    'CloudFormation'
    'CloudWatchLogs'
    'DynamoDBv2'
    'EC2'
    'ECR'
    'ECS'
    'ElasticLoadBalancingV2'
    'EventBridge'
    'IdentityManagement'
    'Lambda'
    'S3'
    'SecretsManager'
    'SecurityToken'
    'StepFunctions'
)

# change display language for gpg.
$env:LANG = 'en'

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
    if ($awsServices) {
        Install-AWSToolsModule -Name $awsServices -Scope AllUsers -Force
    }
}

function Initialize-PackageSource {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    $url = "https://api.nuget.org/v3/index.json"
    Register-PackageSource -Name NuGet -Location $url -ProviderName NuGet -Trusted
}

function Install-Modules {
    Initialize-PackageSource
    $names | Install-NonExistsModule | Out-Null
    Install-AWSModules | Out-Null
}

function Update-Profile {
    $params = @{
        Uri     = https://gist.githubusercontent.com/krymtkts/f8af667c32b16fc28a815243b316c5be/raw/Microsoft.PowerShell_profile.ps1
        OutFile = ~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1
    }
    Invoke-WebRequest @params
}

function Edit-TerminalIcons {
    $ti = Get-Module Terminal-Icons -ErrorAction SilentlyContinue
    if (-not $ti) {
        Write-Error 'Terminal-Icons not found. install it!'
        return
    }
    $params = @{
        Uri     = 'https://gist.githubusercontent.com/krymtkts/4457a23124b2db860a6b32eba6490b03/raw/glyphs.ps1'
        OutFile = "$(Split-Path $ti.Path -Parent)\Data\glyphs.ps1"
    }
    Invoke-WebRequest @params
}

function Edit-EverMonkey {
    $evermonkey = '~\.vscode\extensions\michalyao.evermonkey-2.4.5'
    if (-not $evermonkey) {
        Write-Verbose 'There is no evermonkey.'
        return
    }
    $params = @{
        Uri     = 'https://gist.githubusercontent.com/krymtkts/8a5a3a5a7e1efe9db7f2c6bbda337571/raw/converterplus.js'
        OutFile = "$evermonkey\out\src\converterplus.js"
    }
    Invoke-WebRequest @params
}

function Update-PoshTheme {
    $params = @{
        Uri     = 'https://gist.githubusercontent.com/krymtkts/d320ff5ec30fa47b138c2df018f95423/raw/.oh-my-posh.omp.json'
        OutFile = '~/.oh-my-posh.omp.json'
    }
    Invoke-WebRequest @params
}

function Update-GUIRegistryValues {
    $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
    $key = 'Settings'
    $org = Get-ItemProperty $path | Select-Object -ExpandProperty $key

    $new = @() + $org
    $new[12] = 0x01
    Set-ItemProperty $path -name $key -Value $new

    $path = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
    New-Item -Path $path -Force
    Split-Path $path -Parent | Get-ChildItem
    Set-ItemProperty -Path $path -Name '(Default)' -Value ''

    Stop-Process -Name explorer -Force
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
    git branch --format "%(refname:short)=%(upstream:track)" | Where-Object -FilterScript { $_ -like '*`[gone`]*' } | ConvertFrom-StringData | Select-Object  -ExpandProperty Keys | % { git branch $deleteFlag $_ }
}

function Get-GitGraph {
    git log --graph --all --decorate --abbrev-commit --branches --oneline
}

Set-Alias gitgraph Get-GitGraph -Option AllScope

function Set-GitGlobalConfig {
    git config --global core.autocrlf input
    git config --global core.ignorecase false
    git config --global core.quotepath false
    git config --global core.pager LESSCHARSET=utf-8 less
    git config --global core.sshcommand "'C:\Program Files\OpenSSH-Win64\ssh.exe'"
    git config --global core.excludesfile ~/.gitignore_global
    git config --global push.default simple
    git config --global ghq.root ~/dev
    # TODO: add user configuration.
}

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
function cu { Set-Location ~ }
Set-Alias ~ cu -Option AllScope

# Helper function to edit hosts file.
function Edit-Hosts {
    Start-Process notepad c:\windows\system32\drivers\etc\hosts -verb runas
}

function Update-InstalledModules {
    Get-InstalledModule | Where-Object -Property Repository -eq 'PSGallery' | Update-Module -AllowPrerelease -Scope AllUsers
}

function Update-PipModules {
    $firstTime = -not (Get-Command pip -ErrorAction SilentlyContinue) -and
        (Get-Command pyenv -ErrorAction SilentlyContinue)
    if ($firstTime) {
        $latest = pyenv install -l | Where-Object -FilterScript { -not ($_ -match '[a-zA-Z]') } | Select-Object -Last 1
        pyenv install $latest
        pyenv global $latest
    }
    python -m pip install --upgrade pip
    if ($firstTime) {
        $list = @(
            'boto3'
            'cfn-lint'
            'poetry'
        )
        pip install ($list -join ' ')
    }
    else {
        pip list --outdated | ForEach-Object { [string]::Join(',', $_ -split "\s+") } | `
            ConvertFrom-Csv -Header Package, Version, Latest, Type | `
            Select-Object -Property Package -Skip 2 | `
            ForEach-Object { pip install -U $_.Package }
    }
}

function Install-NodeModules {
    if ((Get-Command npm -ErrorAction SilentlyContinue)) {
        npm install -g fast-cli serverless textlint textlint-rule-preset-ja-technical-writing textlint-rule-date-weekday-mismatch textlint-rule-terminology textlint-rule-write-good
    }
    if (-not (Test-Path ~/.textlint)) {
        @"
{
  "filters": {},
  "rules": {
    "preset-ja-technical-writing": true,
    "date-weekday-mismatch": true,
    "terminology": true,
    "write-good": true
  }
}
"@ | Set-Content ~/.textlintrc -Encoding utf8
    }
}

function Install-GoModules {
    $mods = @(
        'github.com/x-motemen/ghq@latest',
        'mvdan.cc/sh/v3/cmd/shfmt@latest'
    )
    $mods | ForEach-Object {
        $start = $_.LastIndexOf('/') + 1
        $name = $_.Substring($start, $_.Length - '@latest'.Length - $start)
        if (-not (get-command "*$name*" -ErrorAction SilentlyContinue)) {
            go install $_
        }
    }
}

# Helper function to execute choco upgrade.
function Update-Packages {
    Update-InstalledModules
    Update-AWSToolsModule -Scope AllUsers -Force
    Update-PipModules
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

if (Get-Command Set-PoshPrompt -ErrorAction SilentlyContinue) {
    Set-PoshPrompt -Theme ~/.oh-my-posh.omp.json
}
else {
    Set-Theme krymtkts
}

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
        $uppers = "ABCDEFGHIJKLMNPQRSTUVWXYZ"
        $lowers = $uppers.ToLower()
        $digits = "123456789"
        $symbols = "!@#$%^&*()-=[];',./_+{}:`"<>?\|``~"
        $chars = ($uppers + $lowers + $digits + $symbols).ToCharArray()

        do {
            $pwdChars = "".ToCharArray()
            $goodPassword = $false
            $hasDigit = $false
            $hasSymbol = $false
            $pwdChars += (Get-Random -InputObject $uppers.ToCharArray() -Count 1)
            for ($i = 1; $i -lt $length; $i++) {
                $char = Get-Random -InputObject $chars -Count 1
                if ($digits.Contains($char)) { $hasDigit = $true }
                if ($symbols.Contains($char)) { $hasSymbol = $true }
                $pwdChars += $char
            }
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
    # for PyPI installation.
    if ($awsCompleter.Name -notlike '*.exe' ) {
        $f = { python $awsCompleter.Source }
    }
    else {
        $f = { & $awsCompleter.Name }
    }
    Register-ArgumentCompleter -Native -CommandName aws -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        if ("$commandAst" -eq 'aws') {
            # complement the deleted space so that aws_completer lists all services.
            $compLine = "$commandAst "
        }
        else {
            $compLine = $commandAst
        }
        $env:COMP_LINE = $compLine
        $env:COMP_POINT = $cursorPosition
        & $f | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        Remove-Item env:\COMP_LINE
        Remove-Item env:\COMP_POINT
    }
}

function Remove-GitGoneBranches {
    git branch --format '%(refname:short)=%(upstream:track)' | Where-Object -FilterScript { $_ -like '*`[gone`]*' } | ConvertFrom-StringData | Select-Object -ExpandProperty Keys | ForEach-Object { git branch --delete $_ }
}

function New-PsakeFile {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Name = 'psakefile',
        [Parameter()]
        [String[]]
        $Tasks = @('Init', 'Clean', 'Compile', 'Test')
    )
    $psakeFileName = "$Name.ps1"
    New-Item -Name $psakeFileName -ItemType File
    @"
Task default -Depends TestAll

Task TestAll -Depends $($Tasks -join ',')
"@ > $psakeFileName
    foreach ($task in $Tasks) {
        @"

Task $task {
    '$task is running!'
}
"@ >> $psakeFileName
    }
}

# Don't use '$psake' named variable because Invoke-psake has broken if uses the '$psake'.
$psakeCommand = Get-Command -Name Invoke-psake -ErrorAction SilentlyContinue
if ($psakeCommand) {
    Register-ArgumentCompleter -CommandName $psakeCommand.Name -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        "$wordToComplete, $commandAst, $cursorPosition" >> test.log
        Get-ChildItem "$wordToComplete*.ps1" | Select-Object -ExpandProperty Name
    }

    Register-ArgumentCompleter -CommandName $psakeCommand.Name -ParameterName taskList -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        "$commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters" >> test.log
        if ($commandAst -match '(?<file>[^\.]*\.ps1)') {
            $file = $Matches.file
        }
        else {
            $file = 'psakefile.ps1'
        }
        & $commandName -buildFile $file -docs -nologo | Out-String -Stream | ForEach-Object { if ($_ -match "^[^ ]*") { $matches[0] } } | `
            Where-Object { $_ -notin ('Name', '----', '') } | Where-Object { !$wordToComplete -or $_ -like "$wordToComplete*" }
    }
}

if (Get-Command -Name fnm -ErrorAction SilentlyContinue) {
    fnm env --use-on-cd | Out-String | Invoke-Expression
    fnm completions --shell powershell | Out-String | Invoke-Expression
    Get-ChildItem "$env:FNM_MULTISHELL_PATH/../" | Where-Object -Property CreationTime -LE (Get-Date).AddDays(-1) | Remove-Item
}

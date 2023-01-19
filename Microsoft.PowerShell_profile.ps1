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
    'PSReadLine', 'PowerShellGet', 'pocof', 'Get-GzipContent'
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

# TLS versions.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

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
            if (!($modules | Where-Object -Property Name -EQ $n)) {
                Install-Module -Name $n -AllowPrerelease -AllowClobber -Scope AllUsers
            }
            $n
        }
    }
}

function Install-AWSModules {
    if ($awsServices) {
        Find-Module -Name Get-GzipContent | Out-Null # for workaround.
        Install-AWSToolsModule -Name $awsServices -Scope AllUsers -Force -CleanUp
    }
}

function Initialize-PackageSource {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    $url = 'https://api.nuget.org/v3/index.json'
    Register-PackageSource -Name NuGet -Location $url -ProviderName NuGet -Trusted
}

function Install-Modules {
    Initialize-PackageSource
    $names | Install-NonExistsModule | Out-Null
    Install-AWSModules | Out-Null
}

function Update-Profile {
    $profilehome = ($PROFILE | Split-Path -Parent)
    $params = @{
        Uri = 'https://gist.githubusercontent.com/krymtkts/f8af667c32b16fc28a815243b316c5be/raw/Microsoft.PowerShell_profile.ps1'
        OutFile = "$profilehome/Microsoft.PowerShell_profile.ps1"
    }
    Invoke-WebRequest @params

    if (-not (Test-Path "$profilehome\Microsoft.VSCode_profile.ps1")) {
        New-Item -ItemType HardLink -Path $profilehome -Name 'Microsoft.VSCode_profile.ps1' -Value "$profilehome\Microsoft.PowerShell_profile.ps1"
    }
}

function Edit-TerminalIcons {
    $ti = Get-Module Terminal-Icons -ErrorAction SilentlyContinue
    if (-not $ti) {
        Write-Error 'Terminal-Icons not found. install it!'
        return
    }
    $params = @{
        Uri = 'https://gist.githubusercontent.com/krymtkts/4457a23124b2db860a6b32eba6490b03/raw/glyphs.ps1'
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
        Uri = 'https://gist.githubusercontent.com/krymtkts/8a5a3a5a7e1efe9db7f2c6bbda337571/raw/converterplus.js'
        OutFile = "$evermonkey\out\src\converterplus.js"
    }
    Invoke-WebRequest @params
}

function Update-PoshTheme {
    $params = @{
        Uri = 'https://gist.githubusercontent.com/krymtkts/d320ff5ec30fa47b138c2df018f95423/raw/.oh-my-posh.omp.json'
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
    Set-ItemProperty $path -Name $key -Value $new

    $path = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
    New-Item -Path $path -Force
    Split-Path $path -Parent | Get-ChildItem
    Set-ItemProperty -Path $path -Name '(Default)' -Value ''

    Stop-Process -Name explorer -Force
}

function Remove-GitGoneBranches {
    [CmdletBinding()]
    param (
        [switch]$Force
    )
    $deleteFlag = '--delete'
    if ($Force) {
        $deleteFlag = '-D'
    }
    git branch --format '%(refname:short)=%(upstream:track)' | Where-Object -FilterScript { $_ -like '*`[gone`]*' } | ConvertFrom-StringData | Select-Object -ExpandProperty Keys | ForEach-Object { git branch $deleteFlag $_ }
}

function Get-GitGraph {
    git log --graph --all --decorate --abbrev-commit --branches --oneline
}

Set-Alias gitgraph Get-GitGraph -Option AllScope

function Set-GitGlobalConfig {
    git config --global core.autocrlf input
    git config --global core.ignorecase false
    git config --global core.quotepath false
    git config --global core.pager 'LESSCHARSET=utf-8 less'
    git config --global core.sshcommand "'C:\Program Files\OpenSSH-Win64\ssh.exe'"
    git config --global core.excludesfile ~/.gitignore_global
    git config --global push.default simple
    git config --global ghq.root ~/dev
    git config --global init.defaultBranch main
    # TODO: add user configuration.
}

function Set-GPGConfig {
    @'
default-cache-ttl 86400
max-cache-ttl 86400
'@ | Set-Content "$env:APPDATA/gnupg/gpg-agent.conf"

    # currently unused.
    @'
# loopback is not work with VS Code.
# VS Code hang up if you commit with signing.
# pinentry-mode loopback
'@ | Set-Content "$env:APPDATA/gnupg/gpg.conf"
}

function Set-SelectedLocation {
    param(
        [ValidateSet('Add', 'Move', 'Open')]$Mode = 'Move',
        [string]$Location,
        [switch]$Here
    )
    switch ($Mode) {
        'Add' {
            if ($Location) {
                $current = Get-Content '~/.poco-cd'
                $current += "$Location"

            }
            elseif ($Here) {
                $current = Get-Content '~/.poco-cd'
                $current += "$(Get-Location)"
            }
            $current | Get-Unique | Out-File -Encoding UTF8 '~/.poco-cd'
        }
        'Move' {
            Get-Content -Path '~/.poco-cd' | Select-Pocof -CaseSensitive | Select-Object -First 1 | Set-Location
            break
        }
        'Open' {
            Get-Content -Path '~/.poco-cd' | Select-Pocof -CaseSensitive | Select-Object -First 1 | Invoke-Item
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
        [ValidateSet('Add', 'Open')]$Mode = 'Open',
        # Specifies a path to one or more locations.
        [Parameter(
            Position = 0,
            ParameterSetName = 'Path',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Path to one or more locations.')]
        [Alias('PSPath')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Path
    )
    $file = '~/.code-ws'
    switch ($Mode) {
        'Add' {
            if ($Path -and (Test-Path($Path))) {
                $current = Get-Content $file
                $current += (Resolve-Path $Path).Path
                $current | Get-Unique | Out-File -Encoding UTF8 $file
                break
            }
            else {
                Write-Host 'no .code-workspace found.'
            }
        }
        'Open' {
            $ws = Get-Content -Path $file | Where-Object { !$_.StartsWith('#') } | Select-Pocof -CaseSensitive | Select-Object -First 1
            if ($ws.Count -eq 1) {
                code $ws
            }
            break
        }
    }
}
Set-Alias codeof Open-VSCodeWorkspace -Option AllScope


function Set-SelectedRepository {
    ghq list | Select-Pocof | Select-Object -First 1 | ForEach-Object { Set-Location "$(ghq root)/$_" }
}
Set-Alias gcd Set-SelectedRepository -Option AllScope

function Show-Paths() {
    ($Env:Path).split(';') | poco
}

function Show-ReadLineHistory() {
    Get-Content -Path (Get-PSReadLineOption).HistorySavePath | Select-Object -Unique | Select-Pocof -CaseSensitive
}
Set-Alias pghy Show-ReadLineHistory -Option AllScope

function Invoke-ReadLineHistory() {
    Show-ReadLineHistory | Select-Object -First 1 | Invoke-Expression
}
Set-Alias pihy Invoke-ReadLineHistory -Option AllScope

# Helper function to edit hosts file.
function Edit-Hosts {
    Start-Process notepad c:\windows\system32\drivers\etc\hosts -Verb runas
}

function Update-InstalledModules {
    Get-InstalledModule | Where-Object -Property Repository -EQ 'PSGallery' | Update-Module -AllowPrerelease -Scope AllUsers
}

function Update-PipModules {
    if (-not (Get-Command pyenv -ErrorAction SilentlyContinue)) {
        Write-Error "Install pyenv with command below. 'choco install pyenv-win -y'"
        return
    }
    $firstTime = -not (Get-Command pip -ErrorAction SilentlyContinue)
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
        pip list --outdated | ForEach-Object { [string]::Join(',', $_ -split '\s+') } | `
                ConvertFrom-Csv -Header Package, Version, Latest, Type | `
                Select-Object -Property Package -Skip 2 | `
                ForEach-Object { pip install -U $_.Package }
    }
}

function Update-NodeModules {
    if (-not (Get-Command fnm -ErrorAction SilentlyContinue)) {
        Write-Error "Install fnm with command below. 'choco install fnm -y'"
        return
    }
    $firstTime = -not (Get-Command npm -ErrorAction SilentlyContinue)
    if ($firstTime) {
        16, 18 | ForEach-Object { fnm install "v$_" }
        fnm default v18
        fnm env --use-on-cd | Out-String | Invoke-Expression
        fnm completions --shell powershell | Out-String | Invoke-Expression
        npm install -g @google-clasp @openapitools/openapi-generator-cli aws-cdk serverless textlint textlint-rule-preset-ja-technical-writing textlint-rule-date-weekday-mismatch textlint-rule-terminology textlint-rule-write-good wrangler
    }
    else {
        npm update -g
    }
    if (-not (Test-Path ~/.textlint)) {
        @'
{
  "filters": {},
  "rules": {
    "preset-ja-technical-writing": true,
    "date-weekday-mismatch": true,
    "terminology": true,
    "write-good": true
  }
}
'@ | Set-Content ~/.textlintrc -Encoding utf8
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
        if (-not (Get-Command "*$name*" -ErrorAction SilentlyContinue)) {
            go install $_
        }
    }
}

function Update-GoModules {
    ll $env:GOPATH/bin | ForEach-Object {
        go version -m $_
    } | Where-Object {
        $_ -like '*path*'
    } | ConvertFrom-StringData -Delimiter "`t" | Select-Object -ExpandProperty Values | ForEach-Object {
        go install "${_}@latest"
    }
}

# Helper function to execute choco upgrade.
function Update-Packages {
    Update-InstalledModules
    Update-AWSToolsModule -Scope AllUsers -Force -CleanUp
    Update-PipModules
    Update-NodeModules
    Update-GoModules
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
            [Convert]::ToInt32($c -as [char]).ToString('x')
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

function New-Password {
    [CmdletBinding()]
    param (
        # Length is password length.
        [Parameter(Mandatory = $True)]
        [int]
        $Length,
        [Parameter()]
        [switch]
        $NoSymbol
    )

    begin {

    }

    process {
        $uppers = 'ABCDEFGHIJKLMNPQRSTUVWXYZ'
        $lowers = $uppers.ToLower()
        $digits = '123456789'
        $symbols = "!@#$%^&*()-=[];',./_+{}:`"<>?\|``~"
        $chars = if ($NoSymbol) {
            ($uppers + $lowers + $digits).ToCharArray()
        }
        else {
            ($uppers + $lowers + $digits + $symbols).ToCharArray()
        }

        do {
            $pwdChars = ''.ToCharArray()
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
            $password = $pwdChars -join ''
            $goodPassword = $hasDigit -and ($NoSymbol -or $hasSymbol)
        } until ($goodPassword)
    }

    end {
        $password
    }
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

function New-TextFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,
        [Parameter()]
        [long]
        $Byte = [Math]::Pow(1024, 3),
        [Parameter()]
        [int]
        $Basis = [Math]::Pow(1024, 2)
    )
    begin {
        if (Test-Path $Name) {
            Write-Error 'overrides currently not supported.'
            return
        }
        $Remains = $Byte % $Basis
        $Per = $Byte / $Basis
    }
    process {
        1..$Per | ForEach-Object { 'x' * $Basis | Add-Content $Name -Encoding ascii -NoNewline }
        if ($Remains -ne 0) {
            'x' * $Remains | Add-Content $Name -Encoding ascii -NoNewline
        }
    }
}

function ConvertFrom-Base64 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$Value
    )
    process {
        $Value | ForEach-Object {
            $bytes = [System.Convert]::FromBase64String($_)
            $output = [System.Text.Encoding]::Default.GetString($bytes)
            $output
        }
    }
}

function ConvertTo-Base64 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$Value
    )
    process {
        $Value | ForEach-Object {
            # TODO: add encoding.
            [System.Convert]::ToBase64String($_.ToCharArray())
        }
    }
}

function Remove-CurrentVirtualenv {
    if (Test-Path pyproject.toml) {
        poetry env list | Where-Object { $_ -like "*$(Get-Location | Split-Path -Leaf)*" } | Select-Object -First 1 | ForEach-Object { ($_ -split ' ')[0] }
    }
}

function Get-IAMPolicyDocument {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$PolicyArn
    )
    $d = Get-IAMPolicy -PolicyArn $PolicyArn | ForEach-Object {
        Get-IAMPolicyVersion -PolicyArn $_.Arn -VersionId $_.DefaultVersionId
    }
    [System.Reflection.Assembly]::LoadWithPartialName('System.Web.HttpUtility') | Out-Null
    [System.Web.HttpUtility]::UrlDecode($d.Document)
}

function Get-IAMRolePolicyDocument {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$RoleName
    )
    $i = Get-IAMRole -RoleName $RoleName
    [System.Reflection.Assembly]::LoadWithPartialName('System.Web.HttpUtility') | Out-Null
    [System.Web.HttpUtility]::UrlDecode($i.AssumeRolePolicyDocument) | ConvertFrom-Json | ConvertTo-Json -Depth 10
}

function ConvertFrom-CloudFrontAccessLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Path to one or more locations.')]
        [Alias('PSPath')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Path
    )
    begin {
        $header = 'date', 'time', 'x-edge-location', 'sc-bytes', 'c-ip', 'cs-method', 'cs(Host)', 'cs-uri-stem', 'sc-status', 'cs(Referer)', 'cs(User-Agent)', 'cs-uri-query', 'cs(Cookie)', 'x-edge-result-type', 'x-edge-request-id', 'x-host-header', 'cs-protocol', 'cs-bytes', 'time-taken', 'x-forwarded-for', 'ssl-protocol', 'ssl-cipher', 'x-edge-response-result-type', 'cs-protocol-version', 'fle-status', 'fle-encrypted-fields', 'c-port', 'time-to-first-byte', 'x-edge-detailed-result-type', 'sc-content-type', 'sc-content-len', 'sc-range-start', 'sc-range-end'
    }
    process {
        $Path | ForEach-Object { (zcat $_) -split "`n" } | ConvertFrom-Csv -Delimiter "`t" -Header $header
    }
}

function tail {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.Text.Encoding]
        $Encoding = [System.Text.Encoding]::UTF8,
        # Specifies a path to one or more locations.
        [Parameter(
            Position = 0,
            ParameterSetName = 'Path',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Path to one or more locations.')]
        [Alias('PSPath')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int]
        $N = 10
    )
    Get-Content -Path $Path -Wait -Encoding $Encoding -Tail $N
}

function Get-UnixTimeSeconds {
    [CmdletBinding()]
    param (
        [Parameter()]
        [datetime]
        $date = (Get-Date)
    )
    [Math]::Truncate(($date - (Get-Date -UnixTimeSeconds 0)).TotalSeconds)
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

if (Get-Command -Name op -ErrorAction SilentlyContinue) {
    function Get-AWSTemporaryCredential {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param (
            [Parameter()]
            [ValidateNotNullOrEmpty()]
            [String]$ProfileName = $UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [String]$AWSLogin,
            [Parameter()]
            $AWSRegion = 'ap-northeast-1'
        )
        $params = @{
            ProfileName = $ProfileName
            Region = $AWSRegion
        }
        if ($AWSLogin) {
            $params.SerialNumber = (Get-IAMMFADevice -UserName $UserName -ProfileName $ProfileName -Region $AWSRegion).SerialNumber
            $params.TokenCode = (op item get $AWSLogin --otp)
        }
        Get-STSSessionToken @params
    }
    function Set-AWSTemporaryCredential {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param (
            [Parameter()]
            [ValidateNotNullOrEmpty()]
            [String]$ProfileName = $UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [String]$AWSLogin,
            [Parameter()]
            $AWSRegion = 'ap-northeast-1'
        )
        $env:AWS_REGION = $AWSRegion
        $p = @{
            UserName = $UserName
            ProfileName = $ProfileName
            AWSLogin = $AWSLogin
            AWSRegion = $AWSRegion
        }
        $c = Get-AWSTemporaryCredential @p
        $env:AWS_ACCESS_KEY_ID = $c.AccessKeyId
        $env:AWS_SECRET_ACCESS_KEY = $c.SecretAccessKey
        $env:AWS_SESSION_TOKEN = $c.SessionToken
    }
    function Get-AWSRoleCredential {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$RoleName,
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$RoleSessionName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [String]$UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [String]$AWSLogin,
            [Parameter()]
            [ValidateNotNullOrEmpty()]
            [String]$ProfileName = $UserName,
            [Parameter()]
            $AWSRegion = 'ap-northeast-1'
        )
        $params = @{
            RoleArn = "arn:aws:iam::$((Get-STSCallerIdentity -ProfileName $ProfileName -Region $AWSRegion).Account):role/$RoleName"
            RoleSessionName = $RoleSessionName
            ProfileName = $ProfileName
            Region = $AWSRegion
        }
        if ($AWSLogin) {
            $params.SerialNumber = (Get-IAMMFADevice -UserName $UserName -ProfileName $ProfileName -Region $AWSRegion).SerialNumber
            $params.TokenCode = (op item get $AWSLogin --otp)
        }
        Use-STSRole @params | Select-Object -ExpandProperty Credentials
    }
    function Set-AWSRoleCredential {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$RoleName,
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$RoleSessionName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [String]$UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [String]$AWSLogin,
            [Parameter()]
            [ValidateNotNullOrEmpty()]
            [String]$ProfileName = $UserName,
            [Parameter()]
            $AWSRegion = 'ap-northeast-1'
        )
        $env:AWS_REGION = $AWSRegion
        $p = @{
            UserName = $UserName
            ProfileName = $ProfileName
            RoleName = $RoleName
            RoleSessionName = $RoleSessionName
            AWSLogin = $AWSLogin
            AWSRegion = $AWSRegion
        }
        $c = Get-AWSRoleCredential @p
        $env:AWS_ACCESS_KEY_ID = $c.AccessKeyId
        $env:AWS_SECRET_ACCESS_KEY = $c.SecretAccessKey
        $env:AWS_SESSION_TOKEN = $c.SessionToken
    }
}

# Don't use '$psake' named variable because Invoke-psake has broken if uses the '$psake'.
$psakeCommand = Get-Command -Name Invoke-psake -ErrorAction SilentlyContinue
if ($psakeCommand) {
    Register-ArgumentCompleter -CommandName $psakeCommand.Name -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        # "invoke=> [$wordToComplete], [$commandAst], [$cursorPosition]" >> test.log
        Get-ChildItem "$wordToComplete*.ps1" | Resolve-Path -Relative
    }

    Register-ArgumentCompleter -CommandName $psakeCommand.Name -ParameterName taskList -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # "invoke tasklist=> [$commandName], [$parameterName], [$wordToComplete], [$commandAst], [$($fakeBoundParameters|Out-String)]" >> test.log
        if ($commandAst -match '(?<file>[^ ]*\.ps1)') {
            $file = $Matches.file
        }
        else {
            $file = 'psakefile.ps1'
        }
        # "psakefile tasklist=> [$file]" >> test.log
        & $commandName -buildFile $file -docs -nologo | Out-String -Stream | Select-Object -Skip 3 | `
                ForEach-Object { if ($_ -match '^[^ ]+') { $matches[0] } } | `
                Where-Object { !$wordToComplete -or $_ -like "$wordToComplete*" }
    }
}

if (Get-Command -Name fnm -ErrorAction SilentlyContinue) {
    fnm env --use-on-cd | Out-String | Invoke-Expression
    fnm completions --shell powershell | Out-String | Invoke-Expression
    Get-ChildItem "$env:FNM_MULTISHELL_PATH/../" | Where-Object -Property CreationTime -LE (Get-Date).AddDays(-1) | Remove-Item
}

if (Get-Command -Name cdk -ErrorAction SilentlyContinue) {
    function Invoke-CdkBootstrap {
        [CmdletBinding()]
        param (
            [Parameter()]
            [String]$ProfileName
        )
        $env:AWS_REGION = 'ap-northeast-1'
        $ci = Get-STSCallerIdentity
        if ($ProfileName) {
            cdk bootstrap "aws://$($ci.Account)/$($env:AWS_REGION)" --profile $ProfileName
        }
        else {
            cdk bootstrap "aws://$($ci.Account)/$($env:AWS_REGION)"
        }
    }
}

# set a prompt theme.
if (Get-Command -Name oh-my-posh -ErrorAction SilentlyContinue) {
    oh-my-posh init pwsh --config ~/.oh-my-posh.omp.json | Invoke-Expression
}

# Prepare for completions.
Import-Module -Name $completions
# Prepare for Github
Import-Module -Name PowerShellForGitHub
# prepare for Chocolatey.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle ListView
Set-PSReadLineOption -BellStyle Visual

# install ssh-agent service if not exists.
# it will happend after updating Windows OpenSSH.
if (! ($SshAgent = (Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue))) {
    install-sshd.ps1
    Set-Service -Name 'ssh-agent' -StartupType Automatic
    Start-Service ssh-agent
}
elseif ($SshAgent.StartType -eq 'Disabled') {
    Set-Service -Name 'ssh-agent' -StartupType Automatic
    Start-Service ssh-agent
}
else {
    Start-Service ssh-agent
}

# Helper function to set location to the User Profile directory.
function cu { Set-Location ~ }
Set-Alias ~ cu -Option AllScope
# Set alias to ll.
Set-Alias ll ls -Option AllScope

# Show message.
$Horns = [char]::ConvertFromUtf32(0x1f918)
Write-Host "$Horns posh $($PSVersionTable.PSVersion.ToString()) is ready $Horns"

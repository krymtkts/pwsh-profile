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

function local:Set-FunctionsForPSResources {
    $importRequired = @(
        'Terminal-Icons'
        'MavenAutoCompletion'
        'DockerCompletion', 'DockerComposeCompletion'
        'posh-git'
    )
    $pinStable = @(
        'PowerShellGet',
        'platyPS'
    )
    $names = @(
        # basic utilities
        'PSReadLine', 'pocof', 'Get-GzipContent'
        'powershell-yaml', 'PSToml'
        # for PowerShell
        'Microsoft.PowerShell.PSResourceGet', 'PSScriptAnalyzer', 'Pester'
        'psake', 'PSProfiler', 'Microsoft.WinGet.Client'
        # for GitHub
        'PowerShellForGitHub'
        # for AWS
        'AWS.Tools.Installer'
        # others
        'PowerShellAI'
    ) + $pinStable + $importRequired

    Import-Module -Name $importRequired

    function global:Install-NonExistsModule {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter(Mandatory = $True,
                ValueFromPipeline = $True)]
            [string[]]$Name
        )

        begin {
            $modules = Get-InstalledPSResource -Scope AllUsers
        }

        process {
            foreach ($n in $Name) {
                Write-Debug $n
                if (!($modules | Where-Object -Property Name -EQ $n)) {
                    $Prerelease = $n -notin $pinStable
                    Install-PSResource -Name $n -Prerelease:$Prerelease -Scope AllUsers
                }
                $n
            }
        }
    }

    function global:Install-Modules {
        [CmdletBinding(SupportsShouldProcess)]
        param()
        Initialize-PackageSource
        $names | Install-NonExistsModule | Out-Null
        if (Get-Command -Name Install-AWSModules -ErrorAction SilentlyContinue) {
            Install-AWSModules | Out-Null
        }
    }

    function global:Uninstall-OutdatedPSResources {
        [CmdletBinding(SupportsShouldProcess)]
        param()
        Get-InstalledPSResource -Scope AllUsers | Group-Object -Property Name | Where-Object -Property Count -GT 1 | ForEach-Object {
            $_.Group | Sort-Object -Property Version -Descending | Select-Object -Skip 1
        } | Uninstall-PSResource -Scope AllUsers
    }

    function global:Initialize-PackageSource {
        [CmdletBinding(SupportsShouldProcess)]
        param()
        Set-PSResourceRepository -Name PSGallery -Trusted
        $url = 'https://api.nuget.org/v3/index.json'
        Register-PackageSource -Name NuGet -Location $url -ProviderName NuGet -Trusted -Force | Out-Null
    }

    function global:Update-InstalledModules {
        [CmdletBinding(SupportsShouldProcess)]
        param()

        Get-InstalledPSResource -Scope AllUsers | Where-Object -Property Repository -EQ 'PSGallery' | Group-Object -Property Name | ForEach-Object {
            $Prerelease = $_.Name -notin $pinStable
            Write-Host "Update $($_.Name) $(if ($Prerelease) {'Prerelease'} else {''})"
            # NOTE: -WhatIf is not work with Update-PSResource in some cases.
            Update-PSResource -Name $_.Name -Prerelease:$Prerelease -Scope AllUsers
        }
    }
}

function local:Set-FunctionsForAWS {
    $installServicesForAwsToolsForPowerShell = @(

    )
    function global:Install-AWSModules {
        if (-not $installServicesForAwsToolsForPowerShell) {
            Write-Warning 'No AWS services for AWS Tools for PowerShell installed.'
            return
        }
        else {
            Find-Module -Name Get-GzipContent | Out-Null # NOTE: for workaround.
            Install-AWSToolsModule -Name $installServicesForAwsToolsForPowerShell -Scope AllUsers -Force -CleanUp
        }
    }
    function global:Update-AWSModules {
        if (Get-Command -Name Update-AWSToolsModule -ErrorAction SilentlyContinue) {
            Update-AWSToolsModule -Scope AllUsers -Force -CleanUp
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

    if (Get-Command -Name op -ErrorAction SilentlyContinue) {
        function global:Get-AWSTemporaryCredential {
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
        function global:Set-AWSTemporaryCredential {
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
        function global:Get-AWSRoleCredential {
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
                $AWSRegion = 'ap-northeast-1',
                [int]$DurationInSeconds = 3600
            )
            $params = @{
                RoleArn = "arn:aws:iam::$((Get-STSCallerIdentity -ProfileName $ProfileName -Region $AWSRegion).Account):role/$RoleName"
                RoleSessionName = $RoleSessionName
                DurationInSeconds = $DurationInSeconds
                ProfileName = $ProfileName
                Region = $AWSRegion
            }
            if ($AWSLogin) {
                $params.SerialNumber = (Get-IAMMFADevice -UserName $UserName -ProfileName $ProfileName -Region $AWSRegion).SerialNumber
                $params.TokenCode = (op item get $AWSLogin --otp)
            }
            Use-STSRole @params | Select-Object -ExpandProperty Credentials
        }
        function global:Get-AWSRoleCredentialAsEnv {
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
                $AWSRegion = 'ap-northeast-1',
                [int]$DurationInSeconds = 3600
            )
            $p = @{
                ProfileName = $ProfileName
                RoleName = $RoleName
                RoleSessionName = $RoleSessionName
                AWSRegion = $AWSRegion
            }
            if ($AWSLogin) {
                $p.UserName = $UserName
                $p.AWSLogin = $AWSLogin
            }
            Get-AWSRoleCredential @p | ConvertTo-Json | ForEach-Object { $_ -replace '  "(.+)": ', "`$1=" -replace '(,|{|})', '' }
        }
        function global:Set-AWSRoleCredential {
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
                ProfileName = $ProfileName
                RoleName = $RoleName
                RoleSessionName = $RoleSessionName
                AWSRegion = $AWSRegion
            }
            if ($AWSLogin) {
                $p.UserName = $UserName
                $p.AWSLogin = $AWSLogin
            }

            $c = Get-AWSRoleCredential @p
            $env:AWS_ACCESS_KEY_ID = $c.AccessKeyId
            $env:AWS_SECRET_ACCESS_KEY = $c.SecretAccessKey
            $env:AWS_SESSION_TOKEN = $c.SessionToken
        }
    }

    function global:Get-IAMPolicyDocument {
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

    function global:Get-IAMRolePolicyDocument {
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

    function global:ConvertFrom-CloudFrontAccessLog {
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

    if (Get-Command -Name cdk -ErrorAction SilentlyContinue) {
        function global:Invoke-CdkBootstrap {
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

}

function local:Set-FunctionsForGit {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Error 'git is not installed. run `choco install git -y`'
        return
    }
    function global:Remove-GitGoneBranches {
        [CmdletBinding()]
        param (
            [switch]$Force
        )
        $deleteFlag = '--delete'
        if ($Force) {
            $deleteFlag = '-D'
        }
        git remote prune origin
        git branch --format '%(refname:short)=%(upstream:track)' | Where-Object -FilterScript { $_ -like '*`[gone`]*' } | ConvertFrom-StringData | Select-Object -ExpandProperty Keys | ForEach-Object { git branch $deleteFlag $_ }
    }

    function global:Get-GitGraph {
        git log --graph --all --decorate --abbrev-commit --branches --oneline
    }

    Set-Alias gitgraph Get-GitGraph -Option ReadOnly -Force -Scope Global

    function global:Set-GitGlobalConfig {
        git config --global core.autocrlf input
        git config --global core.excludesfile ~/.gitignore_global
        git config --global core.ignorecase false
        git config --global core.longpaths true
        git config --global core.quotepath false
        git config --global core.pager 'LESSCHARSET=utf-8 less'
        git config --global core.sshcommand "'$(Get-Command ssh | Select-Object -ExpandProperty Source)'"
        git config --global ghq.root ~/dev
        git config --global init.defaultBranch main
        git config --global push.default simple

        if ((Get-Command gpg -ErrorAction SilentlyContinue)) {
            git config --global commit.gpgsign true
            git config --global gpg.program "'$(Get-Command gpg | Select-Object -ExpandProperty Source | Resolve-Path | Select-Object -ExpandProperty Path)'"
        }

        git config --global safe.directory="$('~/dev/' | Resolve-Path )*"
    }

    function global:Set-GPGConfig {
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

    if (Get-Command -Name gh -ErrorAction SilentlyContinue) {
        gh completion -s powershell | Out-String | Invoke-Expression
    }
}

function local:Set-FunctionsForEnvironment {
    function global:Update-Profile {
        $ProfileHome = ($PROFILE | Split-Path -Parent)
        $params = @{
            Uri = 'https://raw.githubusercontent.com/krymtkts/pwsh-profile/main/Microsoft.PowerShell_profile.ps1'
            OutFile = "${ProfileHome}/Microsoft.PowerShell_profile.ps1"
        }
        Invoke-WebRequest @params

        if (-not (Test-Path "${ProfileHome}/Microsoft.VSCode_profile.ps1")) {
            New-Item -ItemType HardLink -Path $ProfileHome -Name 'Microsoft.VSCode_profile.ps1' -Value "$profilehome\Microsoft.PowerShell_profile.ps1"
        }
    }

    function global:Edit-TerminalIcons {
        $ti = Get-PSResource Terminal-Icons -ErrorAction SilentlyContinue -Scope AllUsers
        if (-not $ti) {
            Write-Error 'Terminal-Icons not found. install it!'
            return
        }
        $params = @{
            Uri = 'https://gist.githubusercontent.com/krymtkts/4457a23124b2db860a6b32eba6490b03/raw/glyphs.ps1'
            OutFile = "$($ti[0].InstalledLocation)\Data\glyphs.ps1"
        }
        Invoke-WebRequest @params
    }

    function global:Edit-EverMonkey {
        [CmdletBinding()]
        param (
            [Parameter()]
            [ValidateSet('Stable', 'Insider')]
            [string]
            $Channel = 'Insider'
        )
        $evermonkey = switch ($Channel) {
            'Stable' { '~/.vscode/extensions/michalyao.evermonkey-2.4.5' }
            'Insider' { '~/.vscode-insiders/extensions/michalyao.evermonkey-2.4.5' }
            default { throw "Invalid channel $Channel" }
        }
        if (-not $evermonkey) {
            Write-Verbose 'There is no evermonkey.'
            return
        }
        $params = @{
            Uri = 'https://gist.githubusercontent.com/krymtkts/8a5a3a5a7e1efe9db7f2c6bbda337571/raw/converterplus.js'
            OutFile = "$evermonkey/out/src/converterplus.js"
        }
        Invoke-WebRequest @params
    }

    function global:Update-PoshTheme {
        $params = @{
            Uri = 'https://gist.githubusercontent.com/krymtkts/d320ff5ec30fa47b138c2df018f95423/raw/bf406fbf181413c62f0228e56f63db9c57017093/.oh-my-posh.omp.yaml'
            OutFile = '~/.oh-my-posh.omp.yaml'
        }
        Invoke-WebRequest @params
    }

    # No longer used. It can only be used with the old version of Windows 11.
    # function global:Update-GUIRegistryValues {
    #     $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
    #     $key = 'Settings'
    #     $org = Get-ItemProperty $path | Select-Object -ExpandProperty $key

    #     $new = @() + $org
    #     $new[12] = 0x01
    #     Set-ItemProperty $path -Name $key -Value $new

    #     $path = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'
    #     New-Item -Path $path -Force
    #     Split-Path $path -Parent | Get-ChildItem
    #     Set-ItemProperty -Path $path -Name '(Default)' -Value ''

    #     Stop-Process -Name explorer -Force
    # }
}

function local:Set-FunctionsForPocof {
    function global:Set-SelectedLocation {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param(
            [ValidateSet('Add', 'Move', 'Open', 'Remove')]$Mode = 'Move',
            [string]$Location,
            [switch]$Here
        )
        switch ($Mode) {
            'Add' {
                $current = @(Get-Content '~/.poco-cd')
                if ($Location) {
                    $current += "$Location"

                }
                elseif ($Here) {
                    $current += "$(Get-Location)"
                }
                $current | Get-Unique | Set-Content -Encoding UTF8 '~/.poco-cd'
            }
            'Move' {
                Get-Content -Path '~/.poco-cd' | Select-Pocof -CaseSensitive | Select-Object -First 1 | Set-Location
            }
            'Open' {
                Get-Content -Path '~/.poco-cd' | Select-Pocof -CaseSensitive | Select-Object -First 1 | Invoke-Item
            }
            'Remove' {
                if (-not $Location) {
                    $Location = Get-Content -Path '~/.poco-cd' | Select-Pocof -CaseSensitive
                }
                Get-Content '~/.poco-cd' | Where-Object { $_ -ne $Location } | Get-Unique | Set-Content -Encoding UTF8 '~/.poco-cd'
            }
        }
    }
    Set-Alias pcd Set-SelectedLocation -Option ReadOnly -Force -Scope Global

    function global:Invoke-SelectedLocation() {
        Set-SelectedLocation -Mode Open
    }
    Set-Alias pii Invoke-SelectedLocation -Option ReadOnly -Force -Scope Global

    function global:Open-VSCodeWorkspace {
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
            $Path,
            [Parameter()]
            [ValidateSet('Stable', 'Insider')]
            [string]
            $Channel = 'Insider'
        )
        $code = switch ($Channel) {
            'Stable' { 'code' }
            'Insider' { 'code-insiders' }
        }
        $file = '~/.code-ws'
        switch ($Mode) {
            'Add' {
                if ($Path -and (Test-Path($Path))) {
                    $current = @(Get-Content $file)
                    $current += (Resolve-Path $Path).Path
                    $current | Get-Unique | Set-Content -Encoding UTF8 $file
                    break
                }
                else {
                    Write-Host 'no .code-workspace found.'
                }
            }
            'Open' {
                $ws = Get-Content -Path $file | Where-Object { !$_.StartsWith('#') } | Select-Pocof -CaseSensitive | Select-Object -First 1
                if ($ws.Count -eq 1) {
                    & $code $ws
                }
                break
            }
        }
    }
    Set-Alias codeof Open-VSCodeWorkspace -Option ReadOnly -Force -Scope Global

    if (Get-Command ghq -ErrorAction SilentlyContinue) {
        function global:Set-SelectedRepository {
            ghq list | Select-Pocof | Select-Object -First 1 | ForEach-Object { Set-Location "$(ghq root)/$_" }
        }
        Set-Alias gcd Set-SelectedRepository -Option ReadOnly -Force -Scope Global

        if (Get-Command code, code-insiders -ErrorAction SilentlyContinue) {
            function global:Open-SelectedRepository {
                param(
                    [Parameter()]
                    [ValidateSet('Stable', 'Insider')]
                    [string]
                    $Channel = 'Insider'
                )
                $code = switch ($Channel) {
                    'Stable' { 'code' }
                    'Insider' { 'code-insiders' }
                }
                ghq list | Select-Pocof | Select-Object -First 1 | ForEach-Object {
                    Set-Location "$(ghq root)/$_"
                    & $code .
                }
            }
            Set-Alias gcode Open-SelectedRepository -Option ReadOnly -Force -Scope Global
            Set-Alias code code-insiders -Option ReadOnly -Force -Scope Global
        }
        else {
            Write-Error 'code or code-insiders is not installed. run `choco install vscode -y` or `choco install vscode-insiders -y`'
        }
    }
    else {
        Write-Error 'ghq is not installed. run `Install-GoModules`'
    }

    function global:Show-Paths() {
        ($Env:Path).split(';') | Select-Pocof -Layout TopDown
    }

    function global:Show-ReadLineHistory() {
        Get-Content -Path (Get-PSReadLineOption).HistorySavePath | Select-Object -Unique | Select-Pocof -CaseSensitive -Layout TopDown
    }
    Set-Alias pghy Show-ReadLineHistory -Option ReadOnly -Force -Scope Global

    function global:Invoke-ReadLineHistory() {
        Show-ReadLineHistory | Select-Object -First 1 | Invoke-Expression
    }
    Set-Alias pihy Invoke-ReadLineHistory -Option ReadOnly -Force -Scope Global
}

function local:Set-FunctionsForPython {
    function global:Update-PipModules {
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
                'poetry'
                'openai'
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

    function global:Remove-CurrentVirtualenv {
        if (Test-Path pyproject.toml) {
            poetry env list | Where-Object { $_ -like "*$(Get-Location | Split-Path -Leaf)*" } | Select-Object -First 1 | ForEach-Object { ($_ -split ' ')[0] }
        }
    }
}

function local:Set-FunctionsForNodeJs {
    function global:Install-NodeModules {
        npm update -g npm
        npm install -g @google/clasp @openapitools/openapi-generator-cli aws-cdk textlint textlint-rule-preset-ja-technical-writing textlint-rule-date-weekday-mismatch textlint-rule-terminology textlint-rule-write-good wrangler
    }
    function global:Update-NodeModules {
        if (-not (Get-Command fnm -ErrorAction SilentlyContinue)) {
            Write-Error "Install fnm with command below. 'choco install fnm -y'"
            return
        }
        $firstTime = -not (Get-Command npm -ErrorAction SilentlyContinue)
        if ($firstTime) {
            18, 20 | ForEach-Object { fnm install "v$_" }
            fnm default v20
            fnm env --use-on-cd | Out-String | Invoke-Expression
            fnm completions --shell powershell | Out-String | Invoke-Expression
            Install-NodeModules
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

    if (Get-Command -Name fnm -ErrorAction SilentlyContinue) {
        fnm env --use-on-cd | Out-String | Invoke-Expression
        try {
            fnm completions --shell power-shell 2>&1 | Out-String | Invoke-Expression
        }
        catch {
            Write-Warning "fnm completions --shell power-shell failed. $($_)"
        }
        Get-ChildItem "$env:FNM_MULTISHELL_PATH/../" | Where-Object -Property CreationTime -LE (Get-Date).AddDays(-1) | Remove-Item
    }
}

function local:Set-FunctionsForGo {
    function global:Install-GoModules {
        $mods = @(
            'github.com/x-motemen/ghq@latest'
            'mvdan.cc/sh/v3/cmd/shfmt@latest'
            'github.com/jonhadfield/sn-cli/cmd/sncli@latest'
        )
        $mods | ForEach-Object {
            $start = $_.LastIndexOf('/') + 1
            $name = $_.Substring($start, $_.Length - '@latest'.Length - $start)
            if (-not (Get-Command "*$name*" -ErrorAction SilentlyContinue)) {
                go install $_
            }
        }
    }

    function global:Update-GoModules {
        if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
            Write-Error "Install go with command below. 'choco install golang -y'"
            return
        }
        ll $env:GOPATH/bin | ForEach-Object {
            go version -m $_
        } | Where-Object {
            $_ -like '*path*'
        } | ConvertFrom-StringData -Delimiter "`t" | Select-Object -ExpandProperty Values | ForEach-Object {
            go install "${_}@latest"
        }
    }
}

function local:Set-FunctionsForDotnet {
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
    }

    if (Get-Command -Name dotnet -ErrorAction SilentlyContinue) {
        # https://learn.microsoft.com/en-us/dotnet/core/tools/enable-tab-autocomplete#powershell
        Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock {
            # NOTE: The parameter names given in the above document are incorrect.
            # param($commandName, $wordToComplete, $cursorPosition)
            param($wordToComplete, $commandAst, $cursorPosition)
            dotnet complete --position $cursorPosition "$wordToComplete" | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
    }
}

function local:Set-FunctionsForDeno {
    if (Get-Command -Name dvm -ErrorAction SilentlyContinue) {
        dvm completions powershell | Out-String | Invoke-Expression
    }
}

function local:Set-FunctionsForSsh {
    if ((Get-Command -Name ssh -ErrorAction SilentlyContinue) -and (Test-Path "${env:USERPROFILE}/.ssh/config")) {
        function Get-SshHosts {
            Get-Content "${env:USERPROFILE}/.ssh/config" | Where-Object {
                ($_ -ne '') -and ($_ -notlike '#*')
            } | ForEach-Object -Begin {
                $configs = @()
                $tmp = $null
            } -Process {
                $propertyName, $value = $_.Trim() -split '\s+', 2

                if ($propertyName -eq 'Host') {
                    if ($tmp) {
                        $configs += $tmp
                    }
                    $tmp = New-Object PSObject
                }
                $tmp | Add-Member -MemberType NoteProperty -Name $propertyName -Value $value
            } -End {
                if ($tmp) {
                    $configs += $tmp
                }
                $configs
            }
        }
        Register-ArgumentCompleter -Native -CommandName ssh -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)
            Get-SshHosts | Where-Object -Property Host -Like "$wordToComplete*" | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_.Host, $_.Host, 'ParameterValue', $_.Host)
            }
        }
    }

    # NOTE: to install ssh-agent service, run below command.
    # `choco install openssh -params '"/SSHAgentFeature"' -y`
    # don't use `install-sshd.ps1` to prevent from installing sshd service.
}

function local:Set-FunctionsForDocker {
    if (Get-Command -Name docker -ErrorAction SilentlyContinue) {
        function global:Start-DockerSession {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [ArgumentCompleter({
                        [OutputType([System.Management.Automation.CompletionResult])]
                        param(
                            [string] $CommandName,
                            [string] $ParameterName,
                            [string] $WordToComplete,
                            [System.Management.Automation.Language.CommandAst] $CommandAst,
                            [System.Collections.IDictionary] $FakeBoundParameters
                        )
                        docker container ls --format json | ConvertFrom-Json | Where-Object -Property Names -Like "$WordToComplete*" | ForEach-Object {
                            [System.Management.Automation.CompletionResult]::new($_.Names, $_.Names, 'ParameterValue', $_.Names)
                        }
                    })]
                [String]
                $Container,
                [Parameter(Mandatory)]
                [ValidateNotNullOrEmpty()]
                [String]
                $Command
            )
            docker exec --interactive --tty $Container $Command
        }

        # TODO: now work.
        function global:Optimize-DockerUsage {
            # Docker Desktop も dockerd も立ち上がってない前提
            Start-Process 'C:\Program Files\Docker\Docker\resources\dockerd.exe' -WindowStyle Hidden
            # dockerd がいれば docker cli は動かせる
            docker system prune --all --force
            Get-Process '*dockerd*' | ForEach-Object {
                $_.Kill();
                $_.WaitForExit()
            }
            wsl --shutdown
            $vdisk = Resolve-Path ~\AppData\Local\Docker\wsl\data\ext4.vhdx
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
}

function local:Set-FunctionsForStandardNotes {
    # NOTE: command name will be 'sncli' when built with go install.
    Set-Alias sn -Value sncli -Option ReadOnly -Force -Scope Global
    if (Get-Command -Name sn -ErrorAction SilentlyContinue) {
        Register-ArgumentCompleter -Native -Command sn -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)
            Invoke-Expression "$commandAst --generate-bash-completion" | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }

        # NOTE: require `sncli session --add` before use this.
        function global:Open-SnNotes {
            param (
                [Parameter(Mandatory,
                    Position = 0,
                    ValueFromPipeline = $true,
                    ValueFromPipelineByPropertyName = $true)]
                [ValidateNotNullOrEmpty()]
                [String]
                $Title
            )
            $n = sn --use-session get note --title $Title
            if ($n -and ($n -notlike 'no matches*')) {
                $n | ConvertFrom-Json | Select-Object -ExpandProperty items | ForEach-Object {
                    $_.content.text
                } | code -
            }
        }
    }
}

function local:Set-FunctionsForOpenAI {
    $script:OpenAIKeyPath = '~/.openaikey'
    function global:Set-OpenAIAuthentication {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [PSCredential] $Credential
        )

        if (-not $Credential) {
            $message = 'Please provide your OpenAI API key.'
            $message = $message + "These credential is being cached into '${script:OpenAIKeyPath}'."
            $Credential = Get-Credential -Message $message -UserName openai
        }
        if ($PSCmdlet.ShouldProcess($script:OpenAIKeyPath)) {
            $script:OpenAIApiKey = $Credential.Password
            New-Item -Path $script:OpenAIKeyPath -Force | Out-Null
            $Credential.Password | ConvertFrom-SecureString | Set-Content -Path $script:OpenAIKeyPath -Force
        }
    }

    function global:Get-OpenAIAPIKey {
        [CmdletBinding()]
        param(
            [Parameter()]
            [String] $KeyPath = $script:OpenAIKeyPath
        )

        if (Test-Path($KeyPath)) {
            Get-Content $KeyPath | ConvertTo-SecureString
        }
        else {
            $null
        }
    }
}

function local:Set-FunctionsForWinget {
    if (Get-Command -Name winget -ErrorAction SilentlyContinue) {
        Register-ArgumentCompleter -Native -CommandName winget -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)
            [Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.Utf8Encoding]::new()
            $Local:word = $wordToComplete.Replace('"', '""')
            $Local:ast = $commandAst.ToString().Replace('"', '""')
            winget complete --word="$Local:word" --commandline "$Local:ast" --position $cursorPosition | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
    }
}

function local:Set-MiscellaneousFunctions {
    function global:Edit-Hosts {
        Start-Process notepad c:\windows\system32\drivers\etc\hosts -Verb runas
    }

    function global:New-EmptyFIle([parameter(mandatory)][string]$Name) {
        New-Item -Name $Name -ItemType File
    }
    Set-Alias touch New-EmptyFile -Option ReadOnly -Force -Scope Global

    function global:New-TemporaryDirectory {
        $parent = [System.IO.Path]::GetTempPath()
        [string] $name = [System.Guid]::NewGuid()
        New-Item -ItemType Directory -Path (Join-Path $parent $name)
    }
    Set-Alias tmpdir New-TemporaryDirectory -Option ReadOnly -Force -Scope Global

    # Helper function to show Unicode character
    function global:Convert-CodeToUnicode {
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

    function global:Convert-UnicodeToCode {
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

    function global:Convert-0xTo10 {
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

    function global:New-Password {
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

    function global:New-TextFile {
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

    function global:ConvertFrom-Base64 {
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

    function global:ConvertTo-Base64 {
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

    function global:tail {
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

    function global:Get-UnixTimeSeconds {
        [CmdletBinding()]
        param (
            [Parameter()]
            [datetime]
            $date = (Get-Date)
        )
        [Math]::Truncate(($date - (Get-Date -UnixTimeSeconds 0)).TotalSeconds)
    }

    Set-Alias ll ls -Option ReadOnly -Force -Scope Global
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
            $_
        }
    }
}

Set-FunctionsForPSResources
Set-FunctionsForAWS
Set-FunctionsForGit
Set-FunctionsForEnvironment
Set-FunctionsForPocof
Set-FunctionsForPython
Set-FunctionsForNodeJs
Set-FunctionsForGo
Set-FunctionsForDotnet
Set-FunctionsForDeno
Set-FunctionsForSsh
Set-FunctionsForDocker
Set-FunctionsForStandardNotes
Set-FunctionsForOpenAI
Set-FunctionsForWinget
Set-MiscellaneousFunctions

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

# Set default parameter values.
$PSDefaultParameterValues = @{
    'Select-Pocof:Layout' = 'TopDownHalf'
    'Select-Pocof:Prompt' = ''
}

# prepare for Chocolatey.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
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

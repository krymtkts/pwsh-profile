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
    $global:pinStable = @(
        # NOTE: use stable to avoid error in AWS.Tools.Installer.
        'PowerShellGet',
        'platyPS'
    )
    $global:names = @(
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

        Uninstall-OutdatedPSResources
        Get-InstalledPSResource -Scope AllUsers | Where-Object -Property Repository -EQ 'PSGallery' | Group-Object -Property Name | ForEach-Object {
            $Prerelease = $_.Name -notin $pinStable
            Write-Host "Update $($_.Name) $(if ($Prerelease) {'Prerelease'} else {''})"
            # NOTE: -WhatIf is not work with Update-PSResource in some cases.
            Update-PSResource -Name $_.Name -Prerelease:$Prerelease -Scope AllUsers
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

    if (Get-Command -Name 'gpg-connect-agent' -ErrorAction SilentlyContinue) {
        Start-Job -ScriptBlock {
            gpg-connect-agent updatestartuptty /bye
        } | Out-Null
    }
}

function local:Set-FunctionsForEnvironment {
    Get-ChildItem "$($PROFILE | Split-Path -Parent)/Scripts" -Recurse -File -Filter *.psm1 | Import-Module -Force

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

        @(
            'Functions/Functions.psm1'
            'Get-Hash/Get-Hash.psm1'
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
        . $ProfilePath
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

    # TODO: No longer used. It can only be used with the old version of Windows 11.
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
        # NOTE: workaround for certificate issue.
        $env:NODE_TLS_REJECT_UNAUTHORIZED = 0
        npm update -g npm
        npm install -g @google/clasp @openapitools/openapi-generator-cli aws-cdk textlint textlint-rule-preset-ja-technical-writing textlint-rule-date-weekday-mismatch textlint-rule-terminology textlint-rule-write-good wrangler
        $env:NODE_TLS_REJECT_UNAUTHORIZED = 1
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
        Register-ArgumentCompleter -CommandName Invoke-psake -ScriptBlock {
            param($wordToComplete, $commandAst, $cursorPosition)
            # "invoke=> [$wordToComplete], [$commandAst], [$cursorPosition]" >> test.log
            Get-ChildItem "$wordToComplete*.ps1" | Resolve-Path -Relative
        }

        Register-ArgumentCompleter -CommandName Invoke-psake -ParameterName taskList -ScriptBlock {
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
        function global:Get-SshHosts {
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
        # TODO: not work for now.
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
            &$_
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

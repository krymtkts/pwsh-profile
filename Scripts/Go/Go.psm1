[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are used in script blocks and argument completers')]
param ()

function Install-GoModules {
    $mods = @(
        'github.com/x-motemen/ghq@latest'
        'github.com/jonhadfield/sn-cli/cmd/sncli@latest'
        'github.com/wagoodman/dive@latest'
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

if (Get-Command -Name ghq -ErrorAction SilentlyContinue) {
    function global:Get-GhqCommand {
        ghq --help | ForEach-Object -Begin {
            $captureCommand = $false
        } -Process {
            if ($_ -like 'COMMANDS:*' ) {
                $captureCommand = $true
            }
            elseif ($captureCommand -and $_ -ne '') {
                $command = $_.Trim() -split '\s{2,}', 2
                $command[0].Split(',') | ForEach-Object {
                    [PSCustomObject]@{
                        Command = $_.Trim()
                        Description = $command[1]
                    }
                }
            }
            elseif ($captureCommand -and $_ -eq '') {
                $captureCommand = $false
            }
        }
    }
    Register-ArgumentCompleter -Native -CommandName ghq -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        Get-GhqCommand | Where-Object -Property Command -Like "$wordToComplete*" | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_.Command, $_.Command, 'ParameterValue', $_.Description)
        }
    }
}

if (Get-Command -Name dive -ErrorAction SilentlyContinue) {
    dive completion powershell | Out-String | Invoke-Expression
}

if (Test-Path -Path '~/.poco-cd') {
    Move-Item -Path '~/.poco-cd' -Destination '~/.pocof-cd' -Force
}

function Get-PSDefaultParameterValuesForPocof {
    @{
        'Select-Pocof:Layout' = 'TopDownHalf'
        'Select-Pocof:Prompt' = ''
    }
}

$PSDefaultParameterValues += Get-PSDefaultParameterValuesForPocof

function Set-SelectedLocation {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [ValidateSet('Add', 'Move', 'Open', 'Remove')]
        [string]
        $Mode = 'Move',
        [Parameter(
            Position = 0,
            ValueFromPipeline)]
        [string]
        $Location,
        [switch]
        $Here
    )
    $current = Get-Content ('~/.poco-cd', '~/.pocof-cd' | Where-Object { Test-Path -Path $_ } | Select-Object -First 1)
    function Select-One() {
        $loc = $current | Select-Pocof $Location -CaseSensitive -NonInteractive
        if ($loc.Count -eq 1) {
            $loc
        }
        else {
            $current | Select-Pocof $Location -CaseSensitive | Select-Object -First 1
        }
    }
    switch ($Mode) {
        'Add' {
            if ($Location) {
                $current += "$Location"
            }
            elseif ($Here) {
                $current += "$(Get-Location)"
            }
            $current | Sort-Object | Get-Unique | Set-Content -Encoding UTF8 '~/.pocof-cd'
        }
        'Move' {
            Select-One | Set-Location
        }
        'Open' {
            Select-One | Invoke-Item
        }
        'Remove' {
            if (-not $Location) {
                $Location = $current | Select-Pocof -CaseSensitive
            }
            $current | Where-Object { $_ -ne $Location } | Sort-Object | Get-Unique | Set-Content -Encoding UTF8 '~/.pocof-cd'
        }
    }
}
Set-Alias pcd Set-SelectedLocation -Option ReadOnly -Force -Scope Global

function Invoke-SelectedLocation() {
    Set-SelectedLocation -Mode Open
}
Set-Alias pii Invoke-SelectedLocation -Option ReadOnly -Force -Scope Global

if (Get-Command code, code-insiders -ErrorAction SilentlyContinue) {
    function Open-VSCodeWorkspace {
        [CmdletBinding(DefaultParameterSetName = 'Open')]
        param(
            [Parameter(
                Position = 0,
                ParameterSetName = 'Open',
                ValueFromPipeline)]
            [string]
            $Query,
            [Parameter(
                ParameterSetName = 'Open')]
            [ValidateSet('Stable', 'Insider')]
            [string]
            $Channel = 'Insider',
            [Parameter(
                ParameterSetName = 'Add')]
            [switch]
            $Add,
            [Parameter(
                Position = 0,
                ParameterSetName = 'Add',
                ValueFromPipeline,
                ValueFromPipelineByPropertyName,
                HelpMessage = 'Path to one or more locations.')]
            [Alias('PSPath')]
            [ValidateNotNullOrEmpty()]
            [string[]]
            $Path
        )
        $code = switch ($Channel) {
            'Stable' { 'code' }
            'Insider' { 'code-insiders' }
        }
        $file = '~/.code-ws'
        function Open-WorkspaceIfOne($ws) {
            if ($ws.Count -eq 1) {
                & $code $ws
                $true
            }
            $false
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Add' {
                if ($Path -and (Test-Path($Path))) {
                    $current = @(Get-Content $file)
                    $current += (Resolve-Path $Path).Path
                    $current | Sort-Object | Get-Unique | Set-Content -Encoding UTF8 $file
                }
                else {
                    Write-Host 'no .code-workspace found.'
                }
            }
            'Open' {
                $wss = Get-Content -Path $file | Where-Object { !$_.StartsWith('#') }
                $ws = $wss | Select-Pocof $Query -CaseSensitive -NonInteractive
                if (Open-WorkspaceIfOne $ws) {
                    return
                }
                $ws = $wss | Select-Pocof $Query -CaseSensitive | Select-Object -First 1
                Open-WorkspaceIfOne $ws | Out-Null
            }
        }
    }
    Set-Alias codeof Open-VSCodeWorkspace -Option ReadOnly -Force -Scope Global

    if (Get-Command ghq -ErrorAction SilentlyContinue) {
        function Set-SelectedRepository {
            param(
                [Parameter(
                    Position = 0,
                    ValueFromPipeline)]
                [string]
                $Query
            )
            $repos = ghq list
            $repo = $repos | Select-Pocof $Query -NonInteractive
            if ($repo.Count -ne 1) {
                $repo = $repos | Select-Pocof $Query | Select-Object -First 1
            }
            Set-Location "$(ghq root)/$repo"
        }
        Set-Alias gcd Set-SelectedRepository -Option ReadOnly -Force -Scope Global

        function Open-SelectedRepository {
            param(
                [Parameter(
                    Position = 0,
                    ValueFromPipeline)]
                [string]
                $Query,
                [Parameter()]
                [ValidateSet('Stable', 'Insider')]
                [string]
                $Channel = 'Insider'
            )
            $code = switch ($Channel) {
                'Stable' { 'code' }
                'Insider' { 'code-insiders' }
            }
            $repos = ghq list
            function Open-RepoIfOne($repo) {
                if ($repo.Count -eq 1) {
                    Set-Location "$(ghq root)/$repo"
                    & $code .
                    $true
                }
                $false
            }
            $repo = $repos | Select-Pocof $Query -NonInteractive
            if (Open-RepoIfOne $repo) {
                return
            }
            $repo = $repos | Select-Pocof $Query | Select-Object -First 1
            Open-RepoIfOne $repo | Out-Null
        }
        Set-Alias gcode Open-SelectedRepository -Option ReadOnly -Force -Scope Global
        Set-Alias code code-insiders -Option ReadOnly -Force -Scope Global
    }
    else {
        Write-Error 'ghq is not installed. run `Install-GoModules`'
    }
}
else {
    Write-Error 'code or code-insiders is not installed. run `choco install vscode -y` or `choco install vscode-insiders -y`'
}

function Show-Paths() {
        ($Env:Path).split(';') | Select-Pocof -Layout TopDown
}

function Show-ReadLineHistory() {
    Get-Content -Path (Get-PSReadLineOption).HistorySavePath | Select-Pocof -Unique -CaseSensitive -Layout TopDown
}
Set-Alias pghy Show-ReadLineHistory -Option ReadOnly -Force -Scope Global

function Invoke-ReadLineHistory() {
    Show-ReadLineHistory | Select-Object -First 1 | Invoke-Expression
}
Set-Alias pihy Invoke-ReadLineHistory -Option ReadOnly -Force -Scope Global

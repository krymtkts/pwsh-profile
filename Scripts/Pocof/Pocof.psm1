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
        [ValidateSet('Add', 'Move', 'Open', 'Remove')]$Mode = 'Move',
        [string]$Location,
        [switch]$Here
    )
    $current = Get-Content ('~/.poco-cd', '~/.pocof-cd' | Where-Object { Test-Path -Path $_ } | Select-Object -First 1)
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
            $current | Select-Pocof $Location -CaseSensitive | Select-Object -First 1 | Set-Location
        }
        'Open' {
            $current | Select-Pocof -CaseSensitive | Select-Object -First 1 | Invoke-Item
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
                    $current | Sort-Object | Get-Unique | Set-Content -Encoding UTF8 $file
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
        function Set-SelectedRepository {
            ghq list | Select-Pocof | Select-Object -First 1 | ForEach-Object { Set-Location "$(ghq root)/$_" }
        }
        Set-Alias gcd Set-SelectedRepository -Option ReadOnly -Force -Scope Global

        function Open-SelectedRepository {
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

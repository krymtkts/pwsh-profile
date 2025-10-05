function Update-PipModules {
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        Write-Error "Install uv with command below. 'choco install -y uv'"
        return
    }
    $firstTime = -not (Get-Command python -ErrorAction SilentlyContinue)
    if ($firstTime) {
        $latest = '3.13'
        uv python install $latest
        # NOTE: uv doesn't append the path for dll. So, I need to do it manually.
        uv python update-shell
        $list = @(
            'shandy-sqlfmt[jinjafmt]'
        )
        uv tool install ($list -join ' ')
    }
    else {
        uv tool list | Where-Object {
            $_ -notlike '-*'
        } | ForEach-Object {
            $_ -split ' ' | Select-Object -First 1
        } | ForEach-Object {
            uv tool upgrade $_
        }
    }
}

if (Get-Command -Name uv -ErrorAction SilentlyContinue) {
    try {
        uv generate-shell-completion powershell 2>&1 | Out-String | Invoke-Expression
    }
    catch {
        Write-Warning "uv completions --shell power-shell failed. $($_)"
    }
}
else {
    Write-Warning "Install uv with command below. 'choco install uv -y'"
}

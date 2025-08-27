function Resolve-UvPythonPath {
    # NOTE: uv doesn't append the path for dll. So, I need to do it manually.
    Resolve-Path "$($env:APPDATA)/uv/python/*/python*.dll" | Split-Path -Parent | Get-Unique | Sort-Object -Descending | Select-Object -First 1 | ForEach-Object { $env:Path += ';' + $_ }
}

function Update-PipModules {
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        Write-Error "Install uv with command below. 'choco install -y uv'"
        return
    }
    $firstTime = -not (Get-Command pip -ErrorAction SilentlyContinue)
    if ($firstTime) {
        $latest = '3.13'
        uv python install $latest
        Resolve-UvPythonPath
    }
    python -m pip install --upgrade pip
    if ($firstTime) {
        $list = @(
            'sqlfmt'
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

if (Get-Command -Name uv -ErrorAction SilentlyContinue) {
    try {
        uv generate-shell-completion powershell 2>&1 | Out-String | Invoke-Expression
    }
    catch {
        Write-Warning "uv completions --shell power-shell failed. $($_)"
    }
    Resolve-UvPythonPath
}
else {
    Write-Warning "Install uv with command below. 'choco install uv -y'"
}

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

function Remove-CurrentVirtualenv {
    if (Test-Path pyproject.toml) {
        poetry env list | Where-Object { $_ -like "*$(Get-Location | Split-Path -Leaf)*" } | Select-Object -First 1 | ForEach-Object { ($_ -split ' ')[0] }
    }
}


if (Get-Command -Name uv -ErrorAction SilentlyContinue) {
    try {
        uv generate-shell-completion powershell 2>&1 | Out-String | Invoke-Expression
    }
    catch {
        Write-Warning "uv completions --shell power-shell failed. $($_)"
    }
    # NOTE: uv doesn't append the path for dll. So, I need to do it manually.
    Resolve-Path "$($env:APPDATA)/uv/python/*/python*.dll" | Split-Path -Parent | Get-Unique | ForEach-Object { $env:Path += ';' + $_ }
}
else {
    Write-Warning "Install uv with command below. 'choco install uv -y'"
}

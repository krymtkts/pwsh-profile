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
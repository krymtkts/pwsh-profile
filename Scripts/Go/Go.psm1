function Install-GoModules {
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
function Edit-TerminalIcons {
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

function Edit-EverMonkey {
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

function Update-PoshTheme {
    $params = @{
        Uri = 'https://gist.githubusercontent.com/krymtkts/d320ff5ec30fa47b138c2df018f95423/raw/bf406fbf181413c62f0228e56f63db9c57017093/.oh-my-posh.omp.yaml'
        OutFile = '~/.oh-my-posh.omp.yaml'
    }
    Invoke-WebRequest @params
}

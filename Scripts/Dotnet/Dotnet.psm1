if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Error 'dotnet is not installed. run `choco install dotnet -y` or `winget install Microsoft.DotNet.SDK.10` to install it. '
}

# https://learn.microsoft.com/en-us/dotnet/core/tools/enable-tab-autocomplete#powershell
Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock {
    # NOTE: The parameter names given in the above document are incorrect.
    param($wordToComplete, $commandAst, $cursorPosition)
    dotnet complete --position $cursorPosition "$commandAst" | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}

function Set-DotnetGlobalJson {
    [CmdletBinding()]
    param(
        # Path to global.json (default: ./global.json)
        [Parameter(Position = 0)]
        [Alias('PSPath')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path = 'global.json',
        # Target major version (e.g. 10, 9)
        [int]
        $Major = 10,
        # rollForward value to write
        [ValidateSet('disable', 'latestPatch', 'minor', 'latestMinor', 'major', 'latestMajor', 'latestFeature')]
        [string]
        $RollForward = 'latestFeature'
    )

    function Get-LatestDotnetSdkVersionForMajor {
        param(
            [int]$Major
        )

        $sdks = dotnet --list-sdks 2>$null
        if (-not $sdks) {
            throw 'No dotnet SDKs found. Make sure dotnet is on PATH.'
        }

        $versions = $sdks |
            ForEach-Object {
                # "10.0.100 [C:\...]" → "10.0.100"
                ($_ -split '\s+')[0]
            } |
            Where-Object {
                $_ -match '^\d+\.\d+\.\d+' -and $_.StartsWith("$Major.")
            } |
            ForEach-Object {
                [version]$_
            }

        if (-not $versions) {
            throw "No .NET $Major SDKs found. Please install .NET $Major SDK first."
        }

        ($versions | Sort-Object -Descending | Select-Object -First 1).ToString()
    }

    try {
        $version = Get-LatestDotnetSdkVersionForMajor -Major $Major
        Write-Host "Detected latest .NET $Major SDK: $version"

        $jsonObject = @{
            sdk = @{
                version = $version
                rollForward = $RollForward
            }
        }

        $json = $jsonObject | ConvertTo-Json -Depth 3

        $resolved = Resolve-Path -Path $Path -ErrorAction SilentlyContinue
        if ($null -eq $resolved) {
            $targetPath = Join-Path (Get-Location) $Path
            Write-Host "Creating new global.json at: $targetPath"
            $json | Set-Content -Encoding UTF8 $targetPath
        }
        else {
            Write-Host "Updating existing global.json at: $($resolved.Path)"
            $json | Set-Content -Encoding UTF8 $resolved.Path
        }

        Write-Host "global.json updated to use SDK $version (rollForward=$RollForward)." -ForegroundColor Green
    }
    catch {
        Write-Error $_
    }
}

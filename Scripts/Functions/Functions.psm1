function New-EmptyFIle {
    [CmdletBinding()]
    param (
        [parameter(Mandatory)]
        [string]
        $Name
    )
    process {
        New-Item -Name $Name -ItemType File
    }
}
Set-Alias touch New-EmptyFile -Option ReadOnly -Force -Scope Global

function New-TemporaryDirectory {
    [CmdletBinding()]
    param (
        [parameter(Mandatory)]
        [string]
        $Name
    )
    begin {
        $parent = [System.IO.Path]::GetTempPath()
    }
    process {
        [string] $name = [System.Guid]::NewGuid()
        New-Item -ItemType Directory -Path (Join-Path $parent $name)
    }
}
Set-Alias tmpdir New-TemporaryDirectory -Option ReadOnly -Force -Scope Global

function New-TextFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,
        [Parameter()]
        [long]
        $Byte = [Math]::Pow(1024, 3),
        [Parameter()]
        [int]
        $Basis = [Math]::Pow(1024, 2)
    )
    begin {
        if (Test-Path $Name) {
            Write-Error 'overrides currently not supported.'
            return
        }
        $Remains = $Byte % $Basis
        $Per = $Byte / $Basis
    }
    process {
        1..$Per | ForEach-Object { 'x' * $Basis | Add-Content $Name -Encoding ascii -NoNewline }
        if ($Remains -ne 0) {
            'x' * $Remains | Add-Content $Name -Encoding ascii -NoNewline
        }
    }
}

function tail {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.Text.Encoding]
        $Encoding = [System.Text.Encoding]::UTF8,
        # Specifies a path to one or more locations.
        [Parameter(
            Position = 0,
            ParameterSetName = 'Path',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Path to one or more locations.')]
        [Alias('PSPath')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int]
        $N = 10
    )
    Get-Content -Path $Path -Wait -Encoding $Encoding -Tail $N
}

function Invoke-TryCatch {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            Position = 0)]
        [scriptblock]
        $Try,
        [Parameter(
            Mandatory,
            Position = 1)]
        [scriptblock]
        $Catch,
        [Parameter(
            Position = 2)]
        [scriptblock]
        $Finally,
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [object]
        $InputObject
    )
    process {
        try {
            & $Try $InputObject
        }
        catch {
            & $Catch $_.Exception
        }
        finally {
            if ($Finally) {
                & $Finally $InputObject
            }
        }
    }
}

function Get-UnixTimeSeconds {
    [CmdletBinding()]
    param (
        [Parameter()]
        [datetime]
        $date = (Get-Date)
    )
    [Math]::Truncate(($date - (Get-Date -UnixTimeSeconds 0)).TotalSeconds)
}

function Invoke-InfiniteLoop {
    [CmdletBinding()]
    param (
        [Parameter()]
        [scriptblock]
        $ScriptBlock
    )
    end {
        while ($true) {
            if ($ScriptBlock) {
                & $ScriptBlock
            }
        }
    }
}

function Get-BeginningOfMonth {
    [CmdletBinding()]
    param (
        [Parameter(
            Position = 0,
            ValueFromPipeline
        )]
        [datetime]
        $Date = (Get-Date)
    )
    process {
        [datetime]::new($Date.Year, $Date.Month, 1)
    }
}

function Get-EndOfMonth {
    [CmdletBinding()]
    param (
        [Parameter(
            Position = 0,
            ValueFromPipeline
        )]
        [datetime]
        $Date = (Get-Date)
    )
    process {
        [datetime]::new($Date.Year, $Date.Month + 1, 1).AddMicroseconds(-1)
    }
}

function Resolve-HostName {
    [CmdletBinding()]
    param (
        [Parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline
        )]
        [string]
        [ValidateNotNullOrEmpty()]
        $Address
    )
    process {
        [System.Net.Dns]::GetHostEntry($Address)
    }
}

function ConvertTo-LowerCase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string]
        $InputString,
        [switch]
        $InvariantCulture
    )
    process {
        if ($InvariantCulture.IsPresent) {
            $InputString.ToLowerInvariant()
        }
        else {
            $InputString.ToLower()
        }

    }
}

function ConvertTo-UpperCase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string]
        $InputString,
        [switch]
        $InvariantCulture
    )
    process {
        if ($InvariantCulture.IsPresent) {
            $InputString.ToUpperInvariant()
        }
        else {
            $InputString.ToUpper()
        }
    }
}

function ConvertTo-RegexReplacedString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            Position = 0)]
        [string]
        $Pattern,
        [Parameter(Mandatory,
            Position = 1)]
        [string]
        $Replacement,
        [Parameter(Mandatory,
            Position = 2,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string]
        $InputString
    )
    begin {
        $Regex = [regex]::new($Pattern)
    }
    process {
        $Regex.Replace($InputString, $Replacement)
    }
}

function New-Password {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateRange(16, 128)]
        [int]
        $Length,
        [Parameter()]
        [switch]
        $NoSymbol,
        [Parameter()]
        [switch]
        $NoCaseSensitive
    )

    process {
        $uppers = 'ABCDEFGHIJKLMNPQRSTUVWXYZ'
        $lowers = $uppers.ToLower()
        $digits = '123456789'
        $symbols = "!@#$%^&*()-=[];',./_+{}:`"<>?\|``~"
        $chars = (
            ($NoCaseSensitive ? $lowers : $uppers + $lowers) +
            ($NoSymbol ? $digits : $digits + $symbols)
        ).ToCharArray()

        do {
            $pwdChars = @()
            $goodPassword = $false
            $hasUpper = $true
            $hasLower = $true
            $hasDigit = $false
            $hasSymbol = $false
            for ($i = 0; $i -lt $length; $i++) {
                $char = Get-SecureRandom -InputObject $chars -Count 1
                if ($uppers.Contains($char)) { $hasUpper = $true }
                if ($lowers.Contains($char)) { $hasLower = $true }
                if ($digits.Contains($char)) { $hasDigit = $true }
                if ($symbols.Contains($char)) { $hasSymbol = $true }
                $pwdChars += $char
            }
            $password = $pwdChars -join ''
            $goodPassword = (
                $hasLower -and ($NoCaseSensitive -or $hasUpper) -and
                $hasDigit -and ($NoSymbol -or $hasSymbol)
            )
        } until ($goodPassword)

        $password
    }
}

# Helper function to show Unicode character
function Convert-CodeToUnicode {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [int[]] $Code
    )
    process {
        foreach ($c in $Code) {
            if ((0 -le $c) -and ($c -le 0xFFFF)) {
                [char] $c
            }
            elseif ((0x10000 -le $c) -and ($c -le 0x10FFFF)) {
                [char]::ConvertFromUtf32($c)
            }
            else {
                throw "Invalid character code $c"
            }
        }
    }
}

function Convert-UnicodeToCode {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$s
    )
    process {
        foreach ($c in $s) {
            [Convert]::ToInt32($c -as [char]).ToString('x')
        }
    }
}

function Convert-0xTo10 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$0x
    )
    process {
        foreach ($c in $0x) {
            [Convert]::ToInt32($c, 16)
        }
    }
}

function ConvertFrom-Base64 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$Value
    )
    process {
        $Value | ForEach-Object {
            $bytes = [System.Convert]::FromBase64String($_)
            $output = [System.Text.Encoding]::Default.GetString($bytes)
            $output
        }
    }
}

function ConvertTo-Base64 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$Value
    )
    process {
        $Value | ForEach-Object {
            # TODO: add encoding.
            [System.Convert]::ToBase64String($_.ToCharArray())
        }
    }
}

function Split-String {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$Delimiter,
        [Parameter(Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$InputString
    )
    process {
        $InputString | ForEach-Object {
            $_ -split $Delimiter
        }
    }
}

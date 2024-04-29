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
        # Length is password length.
        [Parameter(Mandatory = $True)]
        [int]
        $Length,
        [Parameter()]
        [switch]
        $NoSymbol
    )

    process {
        $uppers = 'ABCDEFGHIJKLMNPQRSTUVWXYZ'
        $lowers = $uppers.ToLower()
        $digits = '123456789'
        $symbols = "!@#$%^&*()-=[];',./_+{}:`"<>?\|``~"
        $chars = if ($NoSymbol) {
        ($uppers + $lowers + $digits).ToCharArray()
        }
        else {
        ($uppers + $lowers + $digits + $symbols).ToCharArray()
        }

        do {
            $pwdChars = ''.ToCharArray()
            $goodPassword = $false
            $hasDigit = $false
            $hasSymbol = $false
            $pwdChars += (Get-Random -InputObject $uppers.ToCharArray() -Count 1)
            for ($i = 1; $i -lt $length; $i++) {
                $char = Get-Random -InputObject $chars -Count 1
                if ($digits.Contains($char)) { $hasDigit = $true }
                if ($symbols.Contains($char)) { $hasSymbol = $true }
                $pwdChars += $char
            }
            $password = $pwdChars -join ''
            $goodPassword = $hasDigit -and ($NoSymbol -or $hasSymbol)
        } until ($goodPassword)
    }

    end {
        $password
    }
}


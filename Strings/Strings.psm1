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


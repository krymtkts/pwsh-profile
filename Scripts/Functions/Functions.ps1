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

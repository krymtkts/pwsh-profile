function Get-Hash {
    param (
        [Parameter(
            Mandatory,
            Position = 0,
            ValueFromPipelineByPropertyName
        )]
        [ArgumentCompleter({
                [OutputType([System.Management.Automation.CompletionResult])]
                param(
                    [string] $CommandName,
                    [string] $ParameterName,
                    [string] $WordToComplete,
                    [System.Management.Automation.Language.CommandAst] $CommandAst,
                    [System.Collections.IDictionary] $FakeBoundParameters
                )
                [System.Security.Cryptography.AesCryptoServiceProvider].Assembly.GetTypes() | Where-Object {
                    ($_.Name.EndsWith('CryptoServiceProvider')) -and ($_.BaseType.BaseType.Name -eq 'HashAlgorithm')
                } | ForEach-Object {
                    $_.Name -replace 'CryptoServiceProvider', ''
                } | Where-Object {
                    $_ -Like "$WordToComplete*"
                } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            })]
        [string]
        $Algorithm,
        [Parameter(
            Position = 1,
            ValueFromPipelineByPropertyName
        )]
        [ArgumentCompleter({
                [OutputType([System.Management.Automation.CompletionResult])]
                param(
                    [string] $CommandName,
                    [string] $ParameterName,
                    [string] $WordToComplete,
                    [System.Management.Automation.Language.CommandAst] $CommandAst,
                    [System.Collections.IDictionary] $FakeBoundParameters
                )
                [System.Text.Encoding].GetProperties('Static, Public') | Where-Object {
                    $_.Name -Like "$WordToComplete*"
                } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterValue', $_.Name)
                }
            })]
        [string]
        $InputEncoding = 'UTF8',
        [Parameter(
            Mandatory,
            Position = 2,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $InputString
    )
    begin {
        $algorithmType = [System.Type]::GetType('System.Security.Cryptography.md5CryptoServiceProvider, System.Security.Cryptography.Csp', $false, $true)
        if (-not $algorithmType) {
            throw "Oops. Unknown hash algorithm: $Algorithm"
        }
        $provider = New-Object $algorithmType
    }

    process {
        $hashBytes = $provider.ComputeHash([System.Text.Encoding]::$InputEncoding.GetBytes($inputString))
        ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLower()
    }
}


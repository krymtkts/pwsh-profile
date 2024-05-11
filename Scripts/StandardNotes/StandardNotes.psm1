# NOTE: command name will be 'sncli' when built with go install.
Set-Alias sn -Value sncli -Option ReadOnly -Force -Scope Global

if (Get-Command -Name sn -ErrorAction SilentlyContinue) {
    Register-ArgumentCompleter -Native -Command sn -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        Invoke-Expression "$commandAst --generate-bash-completion" | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }

    # NOTE: require `sncli session --add` before use this.
    function global:Open-SnNotes {
        param (
            [Parameter(Mandatory,
                Position = 0,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true)]
            [ValidateNotNullOrEmpty()]
            [String]
            $Title
        )
        $n = sn --use-session get note --title $Title
        if ($n -and ($n -notlike 'no matches*')) {
            $n | ConvertFrom-Json | Select-Object -ExpandProperty items | ForEach-Object {
                $_.content.text
            } | code -
        }
    }
}
else {
    Write-Error @'
sn is not found. Install sn with following command.
`Install-GoModules`
'@
}
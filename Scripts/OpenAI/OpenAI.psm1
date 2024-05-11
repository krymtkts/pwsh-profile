# TODO: these functions are currently not used.
function Get-OpenAIKeyPath {
    '~/.openaikey'
}

function Set-OpenAIAuthentication {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [PSCredential] $Credential
    )
    $OpenAIKeyPath = Get-OpenAIKeyPath
    if (-not $Credential) {
        $message = 'Please provide your OpenAI API key.'
        $message = $message + "These credential is being cached into '${OpenAIKeyPath}'."
        $Credential = Get-Credential -Message $message -UserName openai
    }
    if ($PSCmdlet.ShouldProcess($script:OpenAIKeyPath)) {
        $script:OpenAIApiKey = $Credential.Password
        New-Item -Path $script:OpenAIKeyPath -Force | Out-Null
        $Credential.Password | ConvertFrom-SecureString | Set-Content -Path $script:OpenAIKeyPath -Force
    }
}

function Get-OpenAIAPIKey {
    [CmdletBinding()]
    param(
        [Parameter()]
        [String] $KeyPath = (Get-OpenAIKeyPath)
    )

    if (Test-Path($KeyPath)) {
        Get-Content $KeyPath | ConvertTo-SecureString
    }
    else {
        $null
    }
}

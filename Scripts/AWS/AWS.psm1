function Get-AWSModuleConfiguration {
    [CmdletBinding()]
    param ()
    $filePath = Join-Path -Path ($PROFILE | Split-Path -Parent) -ChildPath 'aws-modules.psd1'

    if (-not (Test-Path -Path $filePath)) {
        $result = Read-Host -Prompt "File '$filePath' does not exist. Do you want to create it? (y/n)"
        if ($result -eq 'y') {
            # 配列をpsd1ファイルに保存
            $installServicesForAwsToolsForPowerShell = @()
            $hashTable = @{Services = $installServicesForAwsToolsForPowerShell }
            $hashTable | ConvertTo-Json | Out-File -FilePath $filePath
        }
        else {
            return @()
        }
    }

    $data = Import-PowerShellDataFile -Path $filePath
    $data.Services
}

function Install-AWSModules {
    $installServicesForAwsToolsForPowerShell = Get-AWSModuleConfiguration
    if (-not $installServicesForAwsToolsForPowerShell) {
        Write-Warning 'No AWS services for AWS Tools for PowerShell installed.'
        return
    }
    else {
        Find-Module -Name Get-GzipContent | Out-Null # NOTE: for workaround.
        Install-AWSToolsModule -Name $installServicesForAwsToolsForPowerShell -Scope AllUsers -Force -CleanUp
    }
}
function Update-AWSModules {
    if (Get-Command -Name Update-AWSToolsModule -ErrorAction SilentlyContinue) {
        Update-AWSToolsModule -Scope AllUsers -Force -CleanUp
    }
}

# This idea was inspired by  https://github.com/aws/aws-cli/issues/5309#issuecomment-693941619
if (Get-Command -Name aws_completer -ErrorAction SilentlyContinue) {
    Register-ArgumentCompleter -Native -CommandName aws -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        if ("$commandAst" -eq 'aws') {
            # complement the deleted space so that aws_completer lists all services.
            $compLine = "$commandAst "
        }
        else {
            $compLine = $commandAst
        }
        $env:COMP_LINE = $compLine
        $env:COMP_POINT = $cursorPosition
        aws_completer | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        Remove-Item env:\COMP_LINE
        Remove-Item env:\COMP_POINT
    }
}

if (Get-Command -Name op -ErrorAction SilentlyContinue) {
    function Get-AWSTemporaryCredential {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param (
            [Parameter()]
            [ValidateNotNullOrEmpty()]
            [String]$ProfileName = $UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [String]$AWSLogin,
            [Parameter()]
            $AWSRegion = 'ap-northeast-1'
        )
        $params = @{
            ProfileName = $ProfileName
            Region = $AWSRegion
        }
        if ($AWSLogin) {
            $params.SerialNumber = (Get-IAMMFADevice -UserName $UserName -ProfileName $ProfileName -Region $AWSRegion).SerialNumber
            $params.TokenCode = (op item get $AWSLogin --otp)
        }
        Get-STSSessionToken @params
    }
    function Set-AWSTemporaryCredential {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param (
            [Parameter()]
            [ValidateNotNullOrEmpty()]
            [String]$ProfileName = $UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [String]$AWSLogin,
            [Parameter()]
            $AWSRegion = 'ap-northeast-1'
        )
        $env:AWS_REGION = $AWSRegion
        $p = @{
            UserName = $UserName
            ProfileName = $ProfileName
            AWSLogin = $AWSLogin
            AWSRegion = $AWSRegion
        }
        $c = Get-AWSTemporaryCredential @p
        $env:AWS_ACCESS_KEY_ID = $c.AccessKeyId
        $env:AWS_SECRET_ACCESS_KEY = $c.SecretAccessKey
        $env:AWS_SESSION_TOKEN = $c.SessionToken
    }
    function Get-AWSRoleCredential {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param (
            [Parameter(ParameterSetName = 'Default', Mandatory)]
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            # [ValidateNotNullOrEmpty()]
            [String]$RoleName,
            [Parameter(ParameterSetName = 'Cross', Mandatory)]
            # [ValidateNotNullOrEmpty()]
            [String]$RoleArn,
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$RoleSessionName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [Parameter(ParameterSetName = 'Cross', Mandatory)]
            [String]$UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [Parameter(ParameterSetName = 'Cross', Mandatory)]
            [String]$AWSLogin,
            [Parameter()]
            [ValidateNotNullOrEmpty()]
            [String]$ProfileName = $UserName,
            [Parameter()]
            $AWSRegion = 'ap-northeast-1',
            [int]$DurationInSeconds = 3600
        )
        $params = @{
            RoleArn = if ($RoleArn) { $RoleArn } else { "arn:aws:iam::$((Get-STSCallerIdentity -ProfileName $ProfileName -Region $AWSRegion).Account):role/$RoleName" }
            RoleSessionName = $RoleSessionName
            DurationInSeconds = $DurationInSeconds
            ProfileName = $ProfileName
            Region = $AWSRegion
        }
        if ($AWSLogin) {
            $params.SerialNumber = (Get-IAMMFADevice -UserName $UserName -ProfileName $ProfileName -Region $AWSRegion).SerialNumber
            $params.TokenCode = (op item get $AWSLogin --otp)
        }
        Use-STSRole @params | Select-Object -ExpandProperty Credentials
    }
    function Get-AWSRoleCredentialAsEnv {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param (
            [Parameter(ParameterSetName = 'Default', Mandatory)]
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            # [ValidateNotNullOrEmpty()]
            [String]$RoleName,
            [Parameter(ParameterSetName = 'Cross', Mandatory)]
            # [ValidateNotNullOrEmpty()]
            [String]$RoleArn,
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$RoleSessionName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [Parameter(ParameterSetName = 'Cross', Mandatory)]
            [String]$UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [Parameter(ParameterSetName = 'Cross', Mandatory)]
            [String]$AWSLogin,
            [Parameter()]
            [ValidateNotNullOrEmpty()]
            [String]$ProfileName = $UserName,
            [Parameter()]
            $AWSRegion = 'ap-northeast-1',
            [int]$DurationInSeconds = 3600
        )
        $p = @{
            ProfileName = $ProfileName
            RoleSessionName = $RoleSessionName
            AWSRegion = $AWSRegion
        }
        if ($RoleName) {
            $p.RoleName = $RoleName
        }
        if ($RoleArn) {
            $p.RoleArn = $RoleArn
        }
        if ($AWSLogin) {
            $p.UserName = $UserName
            $p.AWSLogin = $AWSLogin
        }

        Get-AWSRoleCredential @p | ConvertTo-Json | ForEach-Object { $_ -replace '  "(.+)": ', "`$1=" -replace '(,|{|})', '' }
    }
    function Set-AWSRoleCredential {
        [CmdletBinding(DefaultParameterSetName = 'Default')]
        param (
            [Parameter(ParameterSetName = 'Default', Mandatory)]
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            # [ValidateNotNullOrEmpty()]
            [String]$RoleName,
            [Parameter(ParameterSetName = 'Cross', Mandatory)]
            # [ValidateNotNullOrEmpty()]
            [String]$RoleArn,
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$RoleSessionName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [Parameter(ParameterSetName = 'Cross', Mandatory)]
            [String]$UserName,
            [Parameter(ParameterSetName = 'MFA', Mandatory)]
            [Parameter(ParameterSetName = 'Cross', Mandatory)]
            [String]$AWSLogin,
            [Parameter()]
            [ValidateNotNullOrEmpty()]
            [String]$ProfileName = $UserName,
            [Parameter()]
            $AWSRegion = 'ap-northeast-1'
        )
        $env:AWS_REGION = $AWSRegion
        $p = @{
            ProfileName = $ProfileName
            RoleSessionName = $RoleSessionName
            AWSRegion = $AWSRegion
        }
        if ($RoleName) {
            $p.RoleName = $RoleName
        }
        if ($RoleArn) {
            $p.RoleArn = $RoleArn
        }
        if ($AWSLogin) {
            $p.UserName = $UserName
            $p.AWSLogin = $AWSLogin
        }

        $c = Get-AWSRoleCredential @p
        $env:AWS_ACCESS_KEY_ID = $c.AccessKeyId
        $env:AWS_SECRET_ACCESS_KEY = $c.SecretAccessKey
        $env:AWS_SESSION_TOKEN = $c.SessionToken
    }
}

function Get-IAMPolicyDocument {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$PolicyArn
    )
    $d = Get-IAMPolicy -PolicyArn $PolicyArn | ForEach-Object {
        Get-IAMPolicyVersion -PolicyArn $_.Arn -VersionId $_.DefaultVersionId
    }
    [System.Reflection.Assembly]::LoadWithPartialName('System.Web.HttpUtility') | Out-Null
    [System.Web.HttpUtility]::UrlDecode($d.Document)
}

function Get-IAMRolePolicyDocument {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$RoleName
    )
    $i = Get-IAMRole -RoleName $RoleName
    [System.Reflection.Assembly]::LoadWithPartialName('System.Web.HttpUtility') | Out-Null
    [System.Web.HttpUtility]::UrlDecode($i.AssumeRolePolicyDocument) | ConvertFrom-Json | ConvertTo-Json -Depth 10
}

function ConvertFrom-CloudFrontAccessLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Path to one or more locations.')]
        [Alias('PSPath')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Path
    )
    begin {
        $header = 'date', 'time', 'x-edge-location', 'sc-bytes', 'c-ip', 'cs-method', 'cs(Host)', 'cs-uri-stem', 'sc-status', 'cs(Referer)', 'cs(User-Agent)', 'cs-uri-query', 'cs(Cookie)', 'x-edge-result-type', 'x-edge-request-id', 'x-host-header', 'cs-protocol', 'cs-bytes', 'time-taken', 'x-forwarded-for', 'ssl-protocol', 'ssl-cipher', 'x-edge-response-result-type', 'cs-protocol-version', 'fle-status', 'fle-encrypted-fields', 'c-port', 'time-to-first-byte', 'x-edge-detailed-result-type', 'sc-content-type', 'sc-content-len', 'sc-range-start', 'sc-range-end'
    }
    process {
        $Path | ForEach-Object { (zcat $_) -split "`n" } | ConvertFrom-Csv -Delimiter "`t" -Header $header
    }
}

if (Get-Command -Name cdk -ErrorAction SilentlyContinue) {
    function Invoke-CdkBootstrap {
        [CmdletBinding()]
        param (
            [Parameter()]
            [String]$ProfileName
        )
        # NOTE: workaround for certificate issue.
        $env:NODE_TLS_REJECT_UNAUTHORIZED = 0
        $env:AWS_REGION = 'ap-northeast-1'
        $ci = Get-STSCallerIdentity
        if ($ProfileName) {
            cdk bootstrap "aws://$($ci.Account)/$($env:AWS_REGION)" --profile $ProfileName
        }
        else {
            cdk bootstrap "aws://$($ci.Account)/$($env:AWS_REGION)"
        }
        $env:NODE_TLS_REJECT_UNAUTHORIZED = 1
    }
}

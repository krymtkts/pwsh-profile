$importRequired = @(
    'Terminal-Icons'
    'MavenAutoCompletion'
    'DockerCompletion', 'DockerComposeCompletion'
    'posh-git'
)
$pinStable = @(
    # NOTE: use stable to avoid error in AWS.Tools.Installer.
    'PowerShellGet'
)
$names = @(
    # basic utilities
    'PSReadLine', 'pocof', 'Get-GzipContent'
    'powershell-yaml', 'PSToml'
    # for PowerShell
    'Microsoft.PowerShell.PSResourceGet', 'PSScriptAnalyzer', 'Microsoft.PowerShell.PlatyPS'
    'Pester', 'psake', 'PSProfiler'
    # for Windows
    'Microsoft.WinGet.Client', 'Microsoft.WinGet.CommandNotFound'
    # for GitHub
    'PowerShellForGitHub'
    # for AWS
    'AWS.Tools.Installer'
) + $pinStable + $importRequired

Import-Module -Name $importRequired

function Install-NonExistsModule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $True,
            ValueFromPipeline = $True)]
        [string[]]$Name
    )

    begin {
        $modules = Get-InstalledPSResource -Scope AllUsers
    }

    process {
        foreach ($n in $Name) {
            Write-Verbose $n
            if (!($modules | Where-Object -Property Name -EQ $n)) {
                $Prerelease = $n -notin $pinStable
                Install-PSResource -Name $n -Prerelease:$Prerelease -Scope AllUsers
            }
            $n
        }
    }
}

function Install-Modules {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Initialize-PackageSource
    $names | Install-NonExistsModule | Out-Null
    if (Get-Command -Name Install-AWSModules -ErrorAction SilentlyContinue) {
        Install-AWSModules | Out-Null
    }
}

function Uninstall-OutdatedPSResources {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Get-InstalledPSResource -Scope AllUsers | Group-Object -Property Name | Where-Object -Property Count -GT 1 | ForEach-Object {
        $_.Group | Sort-Object -Property Version -Descending | Select-Object -Skip 1
    } | Uninstall-PSResource -Scope AllUsers
}

function Initialize-PackageSource {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Set-PSResourceRepository -Name PSGallery -Trusted
    $url = 'https://api.nuget.org/v3/index.json'
    Register-PackageSource -Name NuGet -Location $url -ProviderName NuGet -Trusted -Force | Out-Null
}

function Update-InstalledModules {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    Uninstall-OutdatedPSResources
    Get-InstalledPSResource -Scope AllUsers | Where-Object -Property Repository -EQ 'PSGallery' | Group-Object -Property Name | ForEach-Object {
        $Prerelease = $_.Name -notin $pinStable
        Write-Host "Update $($_.Name) $(if ($Prerelease) {'Prerelease'} else {''})"
        # NOTE: -WhatIf is not work with Update-PSResource in some cases.
        Update-PSResource -Name $_.Name -Prerelease:$Prerelease -Scope AllUsers
    }
}
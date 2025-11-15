<#
.SYNOPSIS
    This script provides argument completions for various commands.
    If you want to add functions that are not related to completions, move specific complete function to a specific module.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are used in script blocks and argument completers')]
param ()

if (Get-Command -Name dvm -ErrorAction SilentlyContinue) {
    dvm completions powershell | Out-String | Invoke-Expression
}

if ((Get-Command -Name ssh -ErrorAction SilentlyContinue) -and (Test-Path "${env:USERPROFILE}/.ssh/config")) {
    function global:Get-SshHosts {
        Get-Content "${env:USERPROFILE}/.ssh/config" | Where-Object {
            ($_ -ne '') -and ($_ -notlike '#*')
        } | ForEach-Object -Begin {
            $configs = @()
            $tmp = $null
        } -Process {
            $propertyName, $value = $_.Trim() -split '\s+', 2

            if ($propertyName -eq 'Host') {
                if ($tmp) {
                    $configs += $tmp
                }
                $tmp = New-Object PSObject
            }
            $tmp | Add-Member -MemberType NoteProperty -Name $propertyName -Value $value
        } -End {
            if ($tmp) {
                $configs += $tmp
            }
            $configs
        }
    }
    Register-ArgumentCompleter -Native -CommandName ssh -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        Get-SshHosts | Where-Object -Property Host -Like "$wordToComplete*" | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_.Host, $_.Host, 'ParameterValue', $_.Host)
        }
    }
}

if (Get-Command -Name winget -ErrorAction SilentlyContinue) {
    Register-ArgumentCompleter -Native -CommandName winget -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        [Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.Utf8Encoding]::new()
        $Local:word = $wordToComplete.Replace('"', '""')
        $Local:ast = $commandAst.ToString().Replace('"', '""')
        winget complete --word="$Local:word" --commandline "$Local:ast" --position $cursorPosition | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
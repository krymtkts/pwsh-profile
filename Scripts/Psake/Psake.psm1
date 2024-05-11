# NOTE: Don't use '$psake' named variable because Invoke-psake has broken if uses the '$psake'.
if (Get-Command -Name Invoke-psake -ErrorAction SilentlyContinue) {
    Register-ArgumentCompleter -CommandName Invoke-psake -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        # "invoke=> [$wordToComplete], [$commandAst], [$cursorPosition]" >> test.log
        Get-ChildItem "$wordToComplete*.ps1" | Resolve-Path -Relative
    }

    Register-ArgumentCompleter -CommandName Invoke-psake -ParameterName taskList -ScriptBlock {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # "invoke tasklist=> [$commandName], [$parameterName], [$wordToComplete], [$commandAst], [$($fakeBoundParameters|Out-String)]" >> test.log
        if ($commandAst -match '(?<file>[^ ]*\.ps1)') {
            $file = $Matches.file
        }
        else {
            $file = 'psakefile.ps1'
        }
        # "psakefile tasklist=> [$file]" >> test.log
        & $commandName -buildFile $file -docs -nologo | Out-String -Stream | Select-Object -Skip 3 | `
                ForEach-Object { if ($_ -match '^[^ ]+') { $matches[0] } } | `
                Where-Object { !$wordToComplete -or $_ -like "$wordToComplete*" }
    }
}
else {
    Write-Error @'
Invoke-psake is not found. Install psake with following command.
`Install-PSResource -Name psake -Scope AllUsers`
'@
}

function New-PsakeFile {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Name = 'psakefile',
        [Parameter()]
        [String[]]
        $Tasks = @('Init', 'Clean', 'Compile', 'Test')
    )
    $psakeFileName = "$Name.ps1"
    New-Item -Name $psakeFileName -ItemType File
    @"
Task default -Depends TestAll

Task TestAll -Depends $($Tasks -join ',')
"@ > $psakeFileName
    foreach ($task in $Tasks) {
        @"

Task $task {
'$task is running!'
}
"@ >> $psakeFileName
    }
}
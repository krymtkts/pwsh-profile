function Install-NodeModules {
    # NOTE: workaround for certificate issue.
    $env:NODE_TLS_REJECT_UNAUTHORIZED = 0
    npm update -g npm
    npm install -g @google/clasp @openapitools/openapi-generator-cli aws-cdk textlint textlint-rule-preset-ja-technical-writing textlint-rule-date-weekday-mismatch textlint-rule-terminology textlint-rule-write-good wrangler
    $env:NODE_TLS_REJECT_UNAUTHORIZED = 1
}
function Update-NodeModules {
    if (-not (Get-Command fnm -ErrorAction SilentlyContinue)) {
        Write-Error "Install fnm with command below. 'choco install fnm -y'"
        return
    }
    $firstTime = -not (Get-Command npm -ErrorAction SilentlyContinue)
    if ($firstTime) {
        18, 20 | ForEach-Object { fnm install "v$_" }
        fnm default v20
        fnm env --use-on-cd | Out-String | Invoke-Expression
        fnm completions --shell powershell | Out-String | Invoke-Expression
        Install-NodeModules
    }
    else {
        npm update -g
    }
    if (-not (Test-Path ~/.textlint)) {
        @'
{
  "filters": {},
  "rules": {
    "preset-ja-technical-writing": true,
    "date-weekday-mismatch": true,
    "terminology": true,
    "write-good": true
  }
}
'@ | Set-Content ~/.textlintrc -Encoding utf8
    }
}

if (Get-Command -Name fnm -ErrorAction SilentlyContinue) {
    fnm env --use-on-cd | Out-String | Invoke-Expression
    try {
        fnm completions --shell power-shell 2>&1 | Out-String | Invoke-Expression
    }
    catch {
        Write-Warning "fnm completions --shell power-shell failed. $($_)"
    }
    Get-ChildItem "$env:FNM_MULTISHELL_PATH/../" | Where-Object -Property CreationTime -LE (Get-Date).AddDays(-1) | Remove-Item

    Register-ArgumentCompleter -Native -CommandName 'npm' -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)

        $commandAst = "$commandAst".Substring(0, $cursorPosition - $wordToComplete.Length)
        if ($commandAst -match 'npm\s*$') {
            $help = npm --help
            $help = $help[($help.IndexOf('All commands:') + 2)..($help.Count - 1)]
            $help[0..($help.IndexOf('') - 1)] -join '' -split ',' `
            | ForEach-Object { $_.Trim() } `
            | Where-Object { $_ -like "${wordToComplete}*" } `
            | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
        if (-not (Test-Path ./package.json)) {
            return
        }
        if ($commandAst -match 'npm run(-script)?\s*$') {
            Get-Content .\package.json `
            | ConvertFrom-Json `
            | Select-Object -ExpandProperty scripts `
            | Get-Member -MemberType NoteProperty `
            | Where-Object -Property Name -Like "${wordToComplete}*" `
            | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterValue', $_.Definition)
            }
        }
    }

    function Set-CurrentNodeVersionToSystem {
        $defaultNodeJs = Join-Path $env:APPDATA 'fnm' 'node-versions' $(fnm current) 'installation'
        $userPath = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User)
        if (-not ($userPath -contains $defaultNodeJs)) {
            [System.Environment]::SetEnvironmentVariable('PATH', "$defaultNodeJs;$($userPath)", [System.EnvironmentVariableTarget]::User)
        }
    }
}

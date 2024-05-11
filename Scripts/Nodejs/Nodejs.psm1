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
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error 'git is not installed. run `choco install git -y`'
    return
}

if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
    Write-Error 'gpg is not installed. run `choco install gnupg gpg4win -y`'
    return
}

function global:Remove-GitGoneBranches {
    [CmdletBinding()]
    param (
        [switch]$Force
    )
    $deleteFlag = '--delete'
    if ($Force) {
        $deleteFlag = '-D'
    }
    git remote prune origin
    git branch --format '%(refname:short)=%(upstream:track)' | Where-Object -FilterScript { $_ -like '*`[gone`]*' } | ConvertFrom-StringData | Select-Object -ExpandProperty Keys | ForEach-Object { git branch $deleteFlag $_ }
}

function global:Set-GitGlobalConfig {
    git config --global core.autocrlf input
    git config --global core.excludesfile ~/.gitignore_global
    git config --global core.ignorecase false
    git config --global core.longpaths true
    git config --global core.quotepath false
    git config --global core.pager 'LESSCHARSET=utf-8 less'
    git config --global core.sshcommand "'$(Get-Command ssh | Select-Object -ExpandProperty Source)'"
    git config --global ghq.root ~/dev
    git config --global init.defaultBranch main
    git config --global push.default simple

    if ((Get-Command gpg -ErrorAction SilentlyContinue)) {
        git config --global commit.gpgsign true
        git config --global gpg.program "'$(Get-Command gpg | Select-Object -ExpandProperty Source | Resolve-Path | Select-Object -ExpandProperty Path)'"
    }

    git config --global --add safe.directory "$('~/dev/' | Resolve-Path )*"
}

function global:Set-GPGConfig {
    @'
default-cache-ttl 86400
max-cache-ttl 86400
'@ | Set-Content "$env:APPDATA/gnupg/gpg-agent.conf"

    # currently unused.
    @'
# loopback is not work with VS Code.
# VS Code hang up if you commit with signing.
# pinentry-mode loopback
'@ | Set-Content "$env:APPDATA/gnupg/gpg.conf"
}

function New-GitHubComparUrl {
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Repository,
        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FromCommit,
        [Parameter(Mandatory, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ToCommit
    )
    "https://github.com/${Repository}/compare/${FromCommit}...${ToCommit}"
}

function New-GitHubCoAuthoredBy {
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('dependabot', 'github-copilot-code-review', 'github-copilot-coding-agent')]
        $CoAuthor
    )
    # about co-author. https://docs.github.com/en/pull-requests/committing-changes-to-your-project/creating-and-editing-commits/creating-a-commit-with-multiple-authors
    "Co-authored-by: $(switch ($CoAuthor) {
        'dependabot' { 'dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>' }
        'github-copilot-code-review' { 'Copilot <175728472+Copilot@users.noreply.github.com>' }
        'github-copilot-coding-agent' { 'copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com>' }
        Default { throw "Unsupported co-author: $CoAuthor" }
    })"
}

if (Get-Command -Name gh -ErrorAction SilentlyContinue) {
    gh completion -s powershell | Out-String | Invoke-Expression
}

if (Get-Command -Name 'gpgconf' -ErrorAction SilentlyContinue) {
    gpgconf --launch gpg-agent | Out-Null
    # NOTE: open pinentry for caching passphrase.
    'warmup' | gpg --clearsign *> $null
}

param([string]$Owner = 'asif3252')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if ($Owner -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$') { throw 'Invalid GitHub owner.' }
foreach ($program in @('git','gh','py')) {
    if (-not (Get-Command $program -ErrorAction SilentlyContinue)) { throw "Install $program before publishing." }
}
& gh auth status
if ($LASTEXITCODE -ne 0) { throw 'Run gh auth login first.' }
& py -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Tests failed. Publication stopped.' }
if (-not (Test-Path -LiteralPath '.git')) {
    & git init -b main
    if ($LASTEXITCODE -ne 0) { throw 'Git initialization failed.' }
}
$remotes = & git remote
if ($remotes -contains 'origin') { throw 'An origin remote is already configured. Review it before publishing.' }
& git add -- README.md traceguard.py web tests samples docs SECURITY.md CONTRIBUTING.md LICENSE .gitignore .github publish.ps1
if ($LASTEXITCODE -ne 0) { throw 'Staging failed.' }
& git commit -m 'Build TraceGuard offline SOC investigation workbench'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed. Check Git identity and staged changes.' }
& gh repo create "$Owner/TraceGuard" --public --source . --remote origin --push --description 'Offline SOC log triage with explainable detections, evidence review, and SQLite case tracking.'
if ($LASTEXITCODE -ne 0) { throw 'GitHub publication failed; the local commit remains available.' }
Write-Host "Published: https://github.com/$Owner/TraceGuard"

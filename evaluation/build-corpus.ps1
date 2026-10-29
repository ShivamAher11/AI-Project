$ErrorActionPreference = 'Stop'
$repo = (Get-Location).Path
New-Item -ItemType Directory -Force -Path (Join-Path $repo 'evaluation/build') | Out-Null
docker build -f evaluation/Dockerfile -t ai-re-eval-mingw .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker run --rm `
  -v "${repo}/evaluation/src:/src:ro" `
  -v "${repo}/evaluation/build:/out" `
  ai-re-eval-mingw
exit $LASTEXITCODE

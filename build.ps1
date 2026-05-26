# build.ps1 — one-shot Configure + Build for NetLens.
#
# Usage:
#   .\build.ps1                # Release build (default)
#   .\build.ps1 -Config Debug
#
# Output: build\bin\<Config>\NetLens.exe

param(
    [ValidateSet('Release','Debug','RelWithDebInfo','MinSizeRel')]
    [string]$Config = 'Release',

    [string]$Generator = 'Visual Studio 17 2022',
    [string]$Arch      = 'x64'
)

$ErrorActionPreference = 'Stop'

$root  = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root 'build'

if (-not (Test-Path $build)) {
    New-Item -ItemType Directory -Path $build | Out-Null
}

Push-Location $build
try {
    Write-Host "==> Configure  ($Generator | $Arch)" -ForegroundColor Cyan
    & cmake -G $Generator -A $Arch $root
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed (exit $LASTEXITCODE)" }

    Write-Host ""
    Write-Host "==> Build  ($Config)" -ForegroundColor Cyan
    & cmake --build . --config $Config --parallel
    if ($LASTEXITCODE -ne 0) { throw "Build failed (exit $LASTEXITCODE)" }

    $exe = Join-Path $build "bin\$Config\NetLens.exe"
    if (Test-Path $exe) {
        $info = Get-Item $exe
        Write-Host ""
        Write-Host "==> OK" -ForegroundColor Green
        Write-Host ("    {0,-55} {1,10:N0} bytes" -f $exe, $info.Length)
    } else {
        throw "Output NetLens.exe not found at $exe"
    }

    # ------------------------------------------------------------------
    # Auto-release to Z:\Release\NetLens_<version>.exe
    # (only for Release builds and only if Z:\ exists).
    # ------------------------------------------------------------------
    if ($Config -eq 'Release') {
        $releaseDir = 'Z:\Release'
        if (Test-Path $releaseDir) {
            $versionFile = Join-Path $root 'VERSION'
            $version = (Get-Content $versionFile -Raw).Trim()
            $dest = Join-Path $releaseDir ("NetLens_{0}.exe" -f $version)
            try {
                Copy-Item -LiteralPath $exe -Destination $dest -Force
                $dInfo = Get-Item $dest
                Write-Host ""
                Write-Host "==> Released" -ForegroundColor Cyan
                Write-Host ("    {0,-55} {1,10:N0} bytes" -f $dest, $dInfo.Length)
            } catch {
                Write-Warning ("Release copy to {0} failed: {1}" -f $dest, $_.Exception.Message)
            }
        } else {
            Write-Host ""
            Write-Host ("(Z:\Release not present \x2014 skipping release copy.)") -ForegroundColor DarkGray
        }
    }
}
finally {
    Pop-Location
}

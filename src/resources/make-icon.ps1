#requires -version 5
# =============================================================================
# Generates NetLens.ico — a multi-resolution icon with a radar / network-
# scope motif on the brand-blue background. Run once after editing this script;
# the produced .ico is checked in and referenced from app.rc.
# =============================================================================

[CmdletBinding()]
param(
    [string]$OutPath = "$PSScriptRoot\NetLens.ico"
)

Add-Type -AssemblyName System.Drawing

# Brand palette — matches the GUI accent stripe / Start button.
$brandBlue  = [System.Drawing.Color]::FromArgb(255, 31, 78, 162)
$brandDark  = [System.Drawing.Color]::FromArgb(255, 22, 60, 128)
$ringPale   = [System.Drawing.Color]::FromArgb(255, 90, 130, 200)
$ringWhite  = [System.Drawing.Color]::FromArgb(220, 255, 255, 255)
$sweepEdge  = [System.Drawing.Color]::FromArgb(120, 255, 255, 255)
$sweepCore  = [System.Drawing.Color]::FromArgb(255, 220, 240, 255)
$dotGreen   = [System.Drawing.Color]::FromArgb(255, 80, 220, 130)
$dotAmber   = [System.Drawing.Color]::FromArgb(255, 250, 190, 40)

function New-IconFrame {
    param([int]$Size)

    $bmp = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

    $rounded = New-Object System.Drawing.Drawing2D.GraphicsPath
    $cornerRadius = [Math]::Max(2, [int]($Size * 0.18))
    $r = $cornerRadius
    $w = $Size - 1
    $rounded.AddArc(0,         0, $r * 2, $r * 2, 180, 90)
    $rounded.AddArc($w - $r*2, 0, $r * 2, $r * 2, 270, 90)
    $rounded.AddArc($w - $r*2, $w - $r*2, $r * 2, $r * 2,   0, 90)
    $rounded.AddArc(0,         $w - $r*2, $r * 2, $r * 2,  90, 90)
    $rounded.CloseFigure()

    $g.SetClip($rounded)

    # Background — subtle vertical gradient from brand blue to a darker shade.
    $bgRect = New-Object System.Drawing.Rectangle(0, 0, $Size, $Size)
    $bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $bgRect, $brandBlue, $brandDark, 90)
    $g.FillRectangle($bgBrush, $bgRect)
    $bgBrush.Dispose()

    # Concentric radar rings.
    $cx = $Size / 2.0
    $cy = $Size / 2.0
    $ringPen = New-Object System.Drawing.Pen($ringPale, [float]([Math]::Max(1.0, $Size / 64.0)))
    $ringPen.Alignment = [System.Drawing.Drawing2D.PenAlignment]::Center
    foreach ($pct in @(0.30, 0.50, 0.70)) {
        $rad = $Size * $pct / 2.0
        $g.DrawEllipse($ringPen, [float]($cx - $rad), [float]($cy - $rad),
                                  [float]($rad * 2), [float]($rad * 2))
    }
    $ringPen.Dispose()

    # Crosshair lines (faint).
    $crossPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(80, 255, 255, 255),
                                              [float]([Math]::Max(1.0, $Size / 96.0)))
    $rOuter = $Size * 0.70 / 2.0
    $g.DrawLine($crossPen, [float]($cx - $rOuter), [float]$cy, [float]($cx + $rOuter), [float]$cy)
    $g.DrawLine($crossPen, [float]$cx, [float]($cy - $rOuter), [float]$cx, [float]($cy + $rOuter))
    $crossPen.Dispose()

    # Radar sweep — a translucent pie from due-north sweeping 55 degrees clockwise.
    # FillPie's float overload takes individual x/y/w/h floats (the RectangleF
    # overload doesn't exist) so we expand the rect inline.
    $sweepRect = New-Object System.Drawing.RectangleF(
        [float]($cx - $rOuter), [float]($cy - $rOuter),
        [float]($rOuter * 2),   [float]($rOuter * 2))
    $sweepBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $sweepRect, $sweepCore, $sweepEdge, 30)
    $g.FillPie($sweepBrush,
               [float]($cx - $rOuter), [float]($cy - $rOuter),
               [float]($rOuter * 2),   [float]($rOuter * 2),
               [float]-90, [float]55)
    $sweepBrush.Dispose()

    # Two host "blips" — a green one near the inner ring, an amber one further out.
    $dotR = [Math]::Max(2.0, $Size * 0.06)
    $greenBrush = New-Object System.Drawing.SolidBrush($dotGreen)
    $g.FillEllipse($greenBrush,
        [float]($cx + $Size * 0.10 - $dotR), [float]($cy - $Size * 0.05 - $dotR),
        [float]($dotR * 2), [float]($dotR * 2))
    $greenBrush.Dispose()

    $amberBrush = New-Object System.Drawing.SolidBrush($dotAmber)
    $dotR2 = $dotR * 0.85
    $g.FillEllipse($amberBrush,
        [float]($cx - $Size * 0.20 - $dotR2), [float]($cy + $Size * 0.12 - $dotR2),
        [float]($dotR2 * 2), [float]($dotR2 * 2))
    $amberBrush.Dispose()

    # Center dot.
    $centerBrush = New-Object System.Drawing.SolidBrush($ringWhite)
    $cdotR = [Math]::Max(1.5, $Size * 0.04)
    $g.FillEllipse($centerBrush,
        [float]($cx - $cdotR), [float]($cy - $cdotR),
        [float]($cdotR * 2),    [float]($cdotR * 2))
    $centerBrush.Dispose()

    $g.Dispose()
    $rounded.Dispose()
    return $bmp
}

# Render PNG frames at the standard icon sizes.
$sizes  = @(256, 128, 64, 48, 32, 24, 16)
$frames = @()
foreach ($s in $sizes) {
    $frames += [pscustomobject]@{ Size = $s; Bitmap = (New-IconFrame -Size $s) }
}

# --- Pack into an ICO file -------------------------------------------------
# ICONDIR (6 bytes) + ICONDIRENTRY * N (16 bytes each) + PNG/BMP payloads.
$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)

# Header
$bw.Write([UInt16]0)            # reserved
$bw.Write([UInt16]1)            # type = icon
$bw.Write([UInt16]$frames.Count)

# We'll write each entry, then each PNG payload. Compute payloads first so we
# know lengths + offsets.
$pngStreams = @()
foreach ($f in $frames) {
    $pngMs = New-Object System.IO.MemoryStream
    $f.Bitmap.Save($pngMs, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngStreams += $pngMs
}

$entrySize  = 16
$headerSize = 6
$payloadOffset = $headerSize + $entrySize * $frames.Count

for ($i = 0; $i -lt $frames.Count; $i++) {
    $f = $frames[$i]
    $pngLen = [int]$pngStreams[$i].Length
    $dim = if ($f.Size -ge 256) { 0 } else { $f.Size }  # 0 means 256
    $bw.Write([byte]$dim)        # width
    $bw.Write([byte]$dim)        # height
    $bw.Write([byte]0)           # colour count (0 = >256)
    $bw.Write([byte]0)           # reserved
    $bw.Write([UInt16]1)         # color planes
    $bw.Write([UInt16]32)        # bits per pixel
    $bw.Write([UInt32]$pngLen)   # size of image data
    $bw.Write([UInt32]$payloadOffset)
    $payloadOffset += $pngLen
}

# Payloads
foreach ($pngMs in $pngStreams) {
    $pngMs.Position = 0
    $pngMs.CopyTo($ms)
    $pngMs.Dispose()
}

$bw.Flush()
[System.IO.File]::WriteAllBytes($OutPath, $ms.ToArray())
$bw.Dispose()
$ms.Dispose()

foreach ($f in $frames) { $f.Bitmap.Dispose() }

Write-Host "Wrote $OutPath ($([int]((Get-Item $OutPath).Length / 1KB)) KB, $($frames.Count) frames)"

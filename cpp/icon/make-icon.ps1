# Draws the p2proxy icon at every size Windows uses and writes
# cpp\src\app.ico (PNG-compressed entries) plus a 256 px preview PNG.
#   pwsh cpp\icon\make-icon.ps1 [-Preview path.png]
param([string]$Preview = "")

Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = "Stop"

function Draw-Icon([int]$S) {
  $bmp = New-Object System.Drawing.Bitmap $S, $S, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
  $g.Clear([System.Drawing.Color]::Transparent)

  # Rounded tile with a blue diagonal gradient.
  $r = [Math]::Max(2.0, $S * 0.22)
  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $w = $S - 1
  $path.AddArc(0, 0, 2 * $r, 2 * $r, 180, 90)
  $path.AddArc($w - 2 * $r, 0, 2 * $r, 2 * $r, 270, 90)
  $path.AddArc($w - 2 * $r, $w - 2 * $r, 2 * $r, 2 * $r, 0, 90)
  $path.AddArc(0, $w - 2 * $r, 2 * $r, 2 * $r, 90, 90)
  $path.CloseFigure()
  $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush (New-Object System.Drawing.PointF 0, 0), (New-Object System.Drawing.PointF $S, $S), ([System.Drawing.Color]::FromArgb(255, 59, 130, 246)), ([System.Drawing.Color]::FromArgb(255, 30, 58, 138))
  $g.FillPath($grad, $path)

  # Client A (lower left) and exit node B (upper right), joined by the tunnel.
  $small = $S -lt 32
  $ax = $S * 0.29; $ay = $S * 0.71
  $bx = $S * 0.71; $by = $S * 0.29
  $node = if ($small) { $S * 0.15 } else { $S * 0.12 }
  $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(245, 255, 255, 255)), ([Math]::Max(1.6, $S * 0.075))
  $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
  $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
  if ($small) {
    $g.DrawLine($pen, $ax, $ay, $bx, $by)
  } else {
    $g.DrawBezier($pen, $ax, $ay, $ax + $S * 0.06, $S * 0.34, $bx - $S * 0.06, $S * 0.66, $bx, $by)
  }
  $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
  $mint = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 52, 211, 153))
  $g.FillEllipse($white, $ax - $node, $ay - $node, 2 * $node, 2 * $node)
  if (-not $small) {
    $ring = $node + [Math]::Max(1.0, $S * 0.028)
    $g.FillEllipse($white, $bx - $ring, $by - $ring, 2 * $ring, 2 * $ring)
  }
  $g.FillEllipse($mint, $bx - $node, $by - $node, 2 * $node, 2 * $node)

  $g.Dispose()
  $ms = New-Object System.IO.MemoryStream
  $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
  $bmp.Dispose()
  return , $ms.ToArray()
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$images = foreach ($s in $sizes) { , (Draw-Icon $s) }

# ICO: ICONDIR, one ICONDIRENTRY per image, then the PNG data.
$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter $out
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
  $s = $sizes[$i]; $len = $images[$i].Length
  $dim = if ($s -ge 256) { 0 } else { $s }
  $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
  $bw.Write([UInt16]1); $bw.Write([UInt16]32); $bw.Write([UInt32]$len); $bw.Write([UInt32]$offset)
  $offset += $len
}
foreach ($img in $images) { $bw.Write($img) }
$bw.Flush()
$ico = Join-Path $PSScriptRoot "..\src\app.ico"
[IO.File]::WriteAllBytes($ico, $out.ToArray())
"wrote $ico ($($out.Length) bytes, sizes $($sizes -join ', '))"
if ($Preview) {
  [IO.File]::WriteAllBytes($Preview, $images[-1])
  "wrote $Preview"
}

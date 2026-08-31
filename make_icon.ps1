$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$dir = 'C:\Users\necat\AppData\Local\HackerAI\BlockerKiller-v2'
$srcPath = Join-Path $dir 'dnsicon_original.jpg'
if (-not (Test-Path $srcPath)) { $srcPath = Join-Path $dir 'dnsicon.ico' }
$outPath = Join-Path $dir 'dnsicon.ico'

Add-Type -TypeDefinition @"
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;

public static class IcoBuild {
    public static Bitmap MakeSquare(Image src, int size) {
        var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bmp)) {
            g.Clear(Color.Transparent);
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.SmoothingMode = SmoothingMode.HighQuality;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.CompositingQuality = CompositingQuality.HighQuality;
            g.DrawImage(src, 0, 0, size, size);
        }
        KnockoutBlack(bmp);
        return bmp;
    }

    static void KnockoutBlack(Bitmap bmp) {
        var rect = new Rectangle(0, 0, bmp.Width, bmp.Height);
        var data = bmp.LockBits(rect, ImageLockMode.ReadWrite, PixelFormat.Format32bppArgb);
        int bytes = Math.Abs(data.Stride) * bmp.Height;
        byte[] buf = new byte[bytes];
        Marshal.Copy(data.Scan0, buf, 0, bytes);
        for (int i = 0; i < buf.Length; i += 4) {
            byte b = buf[i], g = buf[i+1], r = buf[i+2];
            if (r < 28 && g < 28 && b < 28) buf[i+3] = 0;
        }
        Marshal.Copy(buf, 0, data.Scan0, bytes);
        bmp.UnlockBits(data);
    }

    public static byte[] ToDib(Bitmap bmp) {
        int w = bmp.Width, h = bmp.Height;
        int xorStride = w * 4;
        int andStride = ((w + 31) / 32) * 4;
        using (var ms = new MemoryStream())
        using (var bw = new BinaryWriter(ms)) {
            bw.Write(40);
            bw.Write(w);
            bw.Write(h * 2);
            bw.Write((short)1);
            bw.Write((short)32);
            bw.Write(0);
            bw.Write(xorStride * h + andStride * h);
            bw.Write(0); bw.Write(0); bw.Write(0); bw.Write(0);

            var rect = new Rectangle(0, 0, w, h);
            var data = bmp.LockBits(rect, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            byte[] row = new byte[xorStride];
            for (int y = h - 1; y >= 0; y--) {
                IntPtr p = new IntPtr(data.Scan0.ToInt64() + y * data.Stride);
                Marshal.Copy(p, row, 0, xorStride);
                bw.Write(row);
            }
            bmp.UnlockBits(data);
            bw.Write(new byte[andStride * h]);
            bw.Flush();
            return ms.ToArray();
        }
    }

    public static void WriteIco(string path, int[] sizes, Image src) {
        var images = new byte[sizes.Length][];
        for (int i = 0; i < sizes.Length; i++) {
            using (var bmp = MakeSquare(src, sizes[i]))
                images[i] = ToDib(bmp);
        }
        using (var ms = new MemoryStream())
        using (var bw = new BinaryWriter(ms)) {
            bw.Write((ushort)0);
            bw.Write((ushort)1);
            bw.Write((ushort)sizes.Length);
            int offset = 6 + 16 * sizes.Length;
            for (int i = 0; i < sizes.Length; i++) {
                int s = sizes[i];
                bw.Write((byte)(s < 256 ? s : 0));
                bw.Write((byte)(s < 256 ? s : 0));
                bw.Write((byte)0);
                bw.Write((byte)0);
                bw.Write((ushort)1);
                bw.Write((ushort)32);
                bw.Write((uint)images[i].Length);
                bw.Write((uint)offset);
                offset += images[i].Length;
            }
            foreach (var img in images) bw.Write(img);
            bw.Flush();
            File.WriteAllBytes(path, ms.ToArray());
        }
    }
}
"@ -ReferencedAssemblies System.Drawing.dll

$src = [System.Drawing.Image]::FromFile($srcPath)
[IcoBuild]::WriteIco($outPath, @(16,24,32,48,64,128,256), $src)
$src.Dispose()
Write-Host "OK: ICO written with BMP frames, black made transparent"

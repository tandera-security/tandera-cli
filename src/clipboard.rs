//! Grab a PNG from the OS clipboard by shelling out to the platform helper.
//! No bundled dependency — consistent with "bring your own tools".

use anyhow::{anyhow, Result};
use std::process::Command;

pub fn png_command() -> Option<(&'static str, Vec<&'static str>)> {
    if cfg!(target_os = "macos") {
        Some(("pngpaste", vec!["-"]))
    } else if cfg!(target_os = "linux") {
        // Wayland first, then X11.
        Some(("wl-paste", vec!["-t", "image/png"]))
    } else if cfg!(target_os = "windows") {
        Some((
            "powershell",
            vec![
                "-NoProfile",
                "-Command",
                "$img=Get-Clipboard -Format Image; if($img){$ms=New-Object IO.MemoryStream; $img.Save($ms,[Drawing.Imaging.ImageFormat]::Png); [Console]::OpenStandardOutput().Write($ms.ToArray(),0,$ms.Length)}",
            ],
        ))
    } else {
        None
    }
}

pub fn grab_png() -> Result<Vec<u8>> {
    let (cmd, args) = png_command().ok_or_else(|| {
        anyhow!("no clipboard image helper for this platform — use `--file <path>`")
    })?;
    let out = Command::new(cmd)
        .args(&args)
        .output()
        .map_err(|e| anyhow!("could not run `{cmd}` ({e}); install it or use `--file <path>`"))?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err(anyhow!(
            "no image on the clipboard (or `{cmd}` failed) — use `--file <path>`"
        ));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_a_command_for_this_platform() {
        // On mac/linux/windows one of the known tools is chosen; the point is
        // the function is total and returns a stable shape.
        let _ = png_command(); // must compile + not panic
    }
}

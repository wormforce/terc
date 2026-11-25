use crate::mihomo::ControllerConfig;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn powershell(script: &str) -> Result<Output, String> {
    use std::os::windows::process::CommandExt;
    Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); {script}")]).creation_flags(0x08000000).output().map_err(|e| e.to_string())
}
fn run(script: &str) -> Result<String, String> {
    let out = powershell(script)?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
const KEY: &str = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
pub(crate) fn proxy_state() -> Result<(bool, String), String> {
    let text = run(&format!("$p=Get-ItemProperty -LiteralPath '{}'; @{{enabled=($p.ProxyEnable -eq 1);server=[string]$p.ProxyServer}} | ConvertTo-Json -Compress", KEY))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok((
        v["enabled"].as_bool().unwrap_or(false),
        v["server"].as_str().unwrap_or("").into(),
    ))
}
pub fn detect_proxy() -> (String, bool) {
    ("Windows".into(), proxy_state().is_ok_and(|p| p.0))
}
pub fn set_proxy(http: u16, socks: u16) -> Result<String, String> {
    write_proxy(true, http, socks)
}

fn write_proxy(enable: bool, http: u16, socks: u16) -> Result<String, String> {
    if cfg!(test) {
        return Err("system proxy is never changed under test".into());
    }
    if enable && http == 0 {
        return Err("Windows system proxy requires an HTTP or mixed port".into());
    }
    let mut server = format!("http=127.0.0.1:{http};https=127.0.0.1:{http}");
    if socks > 0 {
        server.push_str(&format!(";socks=127.0.0.1:{socks}"));
    }
    let setting = if enable {
        format!(
            "Set-ItemProperty -LiteralPath '{}' -Name ProxyServer -Value {};",
            KEY,
            quote(&server)
        )
    } else {
        String::new()
    };
    run(&format!(
        r#"{setting} Set-ItemProperty -LiteralPath '{KEY}' -Name ProxyEnable -Type DWord -Value {}; Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class TercInternet {{ [DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l); }}'; foreach ($option in 39,37) {{ if (-not [TercInternet]::InternetSetOption([IntPtr]::Zero,$option,[IntPtr]::Zero,0)) {{ throw 'Cannot refresh Windows proxy settings' }} }}"#,
        u8::from(enable)
    ))?;
    Ok(if enable {
        "Windows proxy enabled"
    } else {
        "Windows proxy disabled"
    }
    .into())
}
pub(crate) fn ours(server: &str, ports: &[u16]) -> bool {
    !server.is_empty()
        && server.split(';').all(|entry| {
            let address = entry.split_once('=').map_or(entry, |(_, v)| v);
            address.rsplit_once(':').is_some_and(|(host, port)| {
                matches!(host, "127.0.0.1" | "localhost" | "[::1]")
                    && port.parse::<u16>().is_ok_and(|p| ports.contains(&p))
            })
        })
}
pub fn release_proxy(ports: &[u16]) -> Result<Option<String>, String> {
    let (enabled, server) = proxy_state()?;
    if enabled && ours(&server, ports) {
        write_proxy(false, 0, 0).map(Some)
    } else {
        Ok(None)
    }
}
pub fn managed_core(cfg: &ControllerConfig) -> Result<(u32, u32), String> {
    let pid: u32 = fs::read_to_string(Path::new(&cfg.config_dir).join("terc-core.pid"))
        .map_err(|_| "This core is managed externally; use its service manager".to_string())?
        .trim()
        .parse()
        .map_err(|_| "Invalid managed core PID")?;
    if pid <= 1 {
        return Err("Invalid managed core PID".into());
    }
    let text = run(&format!("Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object Name,CommandLine | ConvertTo-Json -Compress"))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let command = v["CommandLine"].as_str().unwrap_or("");
    if !v["Name"]
        .as_str()
        .is_some_and(|n| n.eq_ignore_ascii_case("mihomo.exe"))
        || !command.contains(&cfg.config_dir)
    {
        return Err("Managed core is no longer running".into());
    }
    Ok((pid, 1))
}
pub fn unpack_core(part: &Path, fresh: &Path) -> Result<Output, String> {
    powershell(&format!("Add-Type -AssemblyName System.IO.Compression.FileSystem; $z=[IO.Compression.ZipFile]::OpenRead({}); try {{ $e=$z.Entries | Where-Object {{ $_.Name -like '*.exe' }} | Select-Object -First 1; if (-not $e) {{ throw 'Missing Mihomo executable' }}; [IO.Compression.ZipFileExtensions]::ExtractToFile($e,{},$true) }} finally {{ $z.Dispose() }}", quote(&part.to_string_lossy()), quote(&fresh.to_string_lossy())))
}
pub fn random_bytes(bytes: &mut [u8]) -> Option<()> {
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    // The system-preferred RNG takes no algorithm handle and writes exactly length bytes.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            2,
        )
    };
    (status == 0).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zip_core_extracts_executable_and_rejects_damage() {
        let root = std::env::temp_dir().join(format!("terc-windows-zip-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let archive = root.join("core.zip.part");
        let fresh = root.join("mihomo.new");
        run(&format!("Add-Type -AssemblyName System.IO.Compression; $f=[IO.File]::Create({}); $z=[IO.Compression.ZipArchive]::new($f,[IO.Compression.ZipArchiveMode]::Create); try {{ $e=$z.CreateEntry('mihomo-windows-amd64.exe'); $w=[IO.StreamWriter]::new($e.Open()); $w.Write('test-core'); $w.Dispose() }} finally {{ $z.Dispose(); $f.Dispose() }}", quote(&archive.to_string_lossy()))).unwrap();
        let output = unpack_core(&archive, &fresh).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&fresh).unwrap(), b"test-core");
        fs::write(&archive, b"broken zip").unwrap();
        assert!(!unpack_core(&archive, &fresh).unwrap().status.success());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn proxy_ownership() {
        assert!(ours("http=127.0.0.1:7890;https=127.0.0.1:7890", &[7890]));
        assert!(!ours("http=company:8080", &[7890]));
        assert!(!ours("127.0.0.1:7897", &[17890]));
        assert!(ours(
            "http=127.0.0.1:17890;https=127.0.0.1:17890;socks=127.0.0.1:17890",
            &[17890]
        ));
        assert!(!ours("http=127.0.0.1:7890;https=company:8080", &[7890]));
    }
}

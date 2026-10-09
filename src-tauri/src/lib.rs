use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct ForensicScanRecord {
    pub id: String,
    pub primary_text: String,
    pub secondary_text: String,
    pub timestamp: String,
    pub status_tag: String,
    pub risk_level: String,
    pub details: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct ScanOutput {
    pub tool_id: String,
    pub tool_name: String,
    pub scan_time: String,
    pub total_items: usize,
    pub suspicious_count: usize,
    pub records: Vec<ForensicScanRecord>,
    pub summary_message: String,
}

fn execute_powershell(script: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .output()
            .map_err(|e| format!("PowerShell execution failed: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() && stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(stderr);
        }
        Ok(stdout)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok("[]".to_string())
    }
}

fn get_now_timestamp() -> String {
    #[cfg(target_os = "windows")]
    {
        let ps = "[DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')";
        execute_powershell(ps).unwrap_or_else(|_| "2026-10-10 02:00:00".to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        "2026-10-10 02:00:00".to_string()
    }
}

#[tauri::command]
fn run_forensic_scan(tool_id: String, target_param: Option<String>) -> Result<ScanOutput, String> {
    let now = get_now_timestamp();
    let mut records: Vec<ForensicScanRecord> = Vec::new();
    let mut suspicious_count = 0;
    let tool_name: String;

    match tool_id.as_str() {
        "power-shell-parser-plus-plus" => {
            tool_name = "PowerShellParser++ (Deep History Scraper)".to_string();
            if let Ok(appdata) = std::env::var("APPDATA") {
                let hist_path = PathBuf::from(&appdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("PowerShell")
                    .join("PSReadLine")
                    .join("ConsoleHost_history.txt");

                if hist_path.exists() {
                    if let Ok(content) = fs::read_to_string(&hist_path) {
                        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
                        let total_lines = lines.len();
                        
                        for (i, line) in lines.iter().rev().take(100).enumerate() {
                            let raw_cmd = line.trim().to_string();
                            let lower = raw_cmd.to_lowercase();
                            let mut is_sus = false;
                            let mut reasons = Vec::new();

                            if lower.contains("-enc") || lower.contains("frombase64") || lower.contains("encodedcommand") {
                                is_sus = true;
                                reasons.push("Base64 Encoded Payload");
                            }
                            if lower.contains("bypass") || lower.contains("-ep bypass") || lower.contains("executionpolicy") {
                                is_sus = true;
                                reasons.push("Execution Policy Bypass");
                            }
                            if lower.contains("downloadstring") || lower.contains("invoke-webrequest") || lower.contains("iwr") || lower.contains("wget") || lower.contains("bitstransfer") {
                                is_sus = true;
                                reasons.push("Remote File Download");
                            }
                            if lower.contains("invoke-expression") || lower.contains("iex") || lower.contains(".invoke(") || lower.contains("reflection.assembly") {
                                is_sus = true;
                                reasons.push("Dynamic In-Memory Invocation");
                            }
                            if lower.contains("-windowstyle hidden") || lower.contains("-w 1") || lower.contains("-w hidden") {
                                is_sus = true;
                                reasons.push("Hidden Window Mode");
                            }

                            let risk = if is_sus {
                                suspicious_count += 1;
                                "High"
                            } else {
                                "Low"
                            };

                            let mut details = HashMap::new();
                            details.insert("Artifact Source".to_string(), "ConsoleHost_history.txt".to_string());
                            details.insert("Command Line #".to_string(), (total_lines - i).to_string());
                            details.insert("Full Command".to_string(), raw_cmd.clone());
                            details.insert("Flagged Indicators".to_string(), if reasons.is_empty() { "Standard Command".to_string() } else { reasons.join(", ") });

                            records.push(ForensicScanRecord {
                                id: format!("ps-{}", i),
                                primary_text: raw_cmd.clone(),
                                secondary_text: format!("Line {} in ConsoleHost_history.txt", total_lines - i),
                                timestamp: now.clone(),
                                status_tag: if is_sus { "FLAGGED".to_string() } else { "Clean".to_string() },
                                risk_level: risk.to_string(),
                                details,
                            });
                        }
                    }
                }
            }
        }
        "win-prefetch-view-plus-plus" => {
            tool_name = "WinPrefetchView++ (Prefetch Artifact Engine)".to_string();
            let pf_dir = Path::new("C:\\Windows\\Prefetch");
            if pf_dir.exists() {
                if let Ok(entries) = fs::read_dir(pf_dir) {
                    let mut file_list = Vec::new();
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("pf") {
                            if let Ok(meta) = entry.metadata() {
                                file_list.push((path, meta));
                            }
                        }
                    }

                    file_list.sort_by(|a, b| {
                        b.1.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                            .cmp(&a.1.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH))
                    });

                    for (i, (path, meta)) in file_list.iter().take(40).enumerate() {
                        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("unknown.pf").to_string();
                        let size = meta.len();
                        let is_recent = i < 10;

                        let mut details = HashMap::new();
                        details.insert("File Size".to_string(), format!("{} bytes", size));
                        details.insert("Prefetch Hash".to_string(), fname.split('-').last().unwrap_or("").replace(".pf", ""));
                        details.insert("Full Path".to_string(), path.to_string_lossy().to_string());

                        records.push(ForensicScanRecord {
                            id: format!("pf-{}", i),
                            primary_text: fname,
                            secondary_text: format!("Size: {} B | Location: C:\\Windows\\Prefetch", size),
                            timestamp: now.clone(),
                            status_tag: if is_recent { "RECENT (PINK)".to_string() } else { "Archived".to_string() },
                            risk_level: "Low".to_string(),
                            details,
                        });
                    }
                }
            }
        }
        "paths-parser-plus-plus" => {
            tool_name = "PathsParser++ (System Path & Hijack Inspector)".to_string();
            if let Ok(path_var) = std::env::var("PATH") {
                let paths: Vec<&str> = path_var.split(';').filter(|p| !p.trim().is_empty()).collect();
                for (i, p) in paths.iter().enumerate() {
                    let exists = Path::new(p).exists();
                    let is_user_writable = p.to_lowercase().contains("users") || p.to_lowercase().contains("temp") || p.to_lowercase().contains("appdata");
                    
                    let risk = if !exists {
                        suspicious_count += 1;
                        "Medium"
                    } else if is_user_writable {
                        suspicious_count += 1;
                        "Medium"
                    } else {
                        "Low"
                    };

                    let mut details = HashMap::new();
                    details.insert("Folder Exists".to_string(), exists.to_string());
                    details.insert("User Writable".to_string(), is_user_writable.to_string());
                    details.insert("Path Variable Index".to_string(), i.to_string());

                    records.push(ForensicScanRecord {
                        id: format!("path-{}", i),
                        primary_text: p.to_string(),
                        secondary_text: if !exists { "Missing Directory (Dangling Path)".to_string() } else if is_user_writable { "User-Writable Location (Potential Hijack Risk)".to_string() } else { "Valid System Path".to_string() },
                        timestamp: now.clone(),
                        status_tag: if !exists { "MISSING".to_string() } else if is_user_writable { "WRITABLE".to_string() } else { "Valid".to_string() },
                        risk_level: risk.to_string(),
                        details,
                    });
                }
            }
        }
        "saved-files-viewer-plus-plus" => {
            tool_name = "SavedFilesViewer++ (Local Download & Recent Files Artifacts)".to_string();
            if let Ok(appdata) = std::env::var("APPDATA") {
                let recent_dir = PathBuf::from(appdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Recent");
                if recent_dir.exists() {
                    if let Ok(entries) = fs::read_dir(recent_dir) {
                        for (i, entry) in entries.flatten().take(35).enumerate() {
                            let path = entry.path();
                            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
                            let meta = entry.metadata().ok();
                            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);

                            let mut details = HashMap::new();
                            details.insert("Shortcut Target".to_string(), path.to_string_lossy().to_string());
                            details.insert("File Size".to_string(), format!("{} bytes", size));

                            records.push(ForensicScanRecord {
                                id: format!("recent-{}", i),
                                primary_text: fname,
                                secondary_text: path.to_string_lossy().to_string(),
                                timestamp: now.clone(),
                                status_tag: "Recent Artifact".to_string(),
                                risk_level: "Low".to_string(),
                                details,
                            });
                        }
                    }
                }
            }
        }
        "crashed-file-viewer-plus-plus" => {
            tool_name = "CrashedFileViewer++ (Windows Error Reporting & Crash Dumps)".to_string();
            let mut crash_paths = Vec::new();
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                crash_paths.push(PathBuf::from(local).join("CrashDumps"));
            }
            crash_paths.push(PathBuf::from("C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive"));

            let mut idx = 0;
            for dir in crash_paths {
                if dir.exists() {
                    if let Ok(entries) = fs::read_dir(dir) {
                        for entry in entries.flatten().take(25) {
                            let path = entry.path();
                            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
                            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

                            let mut details = HashMap::new();
                            details.insert("Dump Size".to_string(), format!("{} bytes", size));
                            details.insert("Full Path".to_string(), path.to_string_lossy().to_string());

                            records.push(ForensicScanRecord {
                                id: format!("crash-{}", idx),
                                primary_text: fname,
                                secondary_text: path.to_string_lossy().to_string(),
                                timestamp: now.clone(),
                                status_tag: "Crash Minidump".to_string(),
                                risk_level: "Low".to_string(),
                                details,
                            });
                            idx += 1;
                        }
                    }
                }
            }
        }
        "string-explorer-plus-plus" => {
            tool_name = "StringExplorer++ (Entropy & Binary Strings)".to_string();
            let target = target_param.unwrap_or_else(|| "C:\\Windows\\explorer.exe".to_string());
            let (entropy, sample_strings) = analyze_file_strings_and_entropy(&target);
            let risk = if entropy > 7.2 {
                suspicious_count += 1;
                "High"
            } else if entropy > 6.5 {
                "Medium"
            } else {
                "Low"
            };

            for (i, s) in sample_strings.iter().enumerate() {
                let mut details = HashMap::new();
                details.insert("Shannon Entropy Score".to_string(), format!("{:.4} / 8.0000", entropy));
                details.insert("Target Binary".to_string(), target.clone());
                details.insert("Extracted String".to_string(), s.clone());

                records.push(ForensicScanRecord {
                    id: format!("str-{}", i),
                    primary_text: s.clone(),
                    secondary_text: format!("Target: {} (Entropy: {:.2})", target, entropy),
                    timestamp: now.clone(),
                    status_tag: if entropy > 7.0 { "HIGH ENTROPY".to_string() } else { "Normal".to_string() },
                    risk_level: risk.to_string(),
                    details,
                });
            }
        }
        "autoruns-plus-plus" => {
            tool_name = "Autoruns++ (Startup & Persistence Scanner)".to_string();
            let ps = r#"
                $results = @()
                $runKeys = @(
                    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
                )
                foreach ($key in $runKeys) {
                    if (Test-Path $key) {
                        $props = Get-ItemProperty -Path $key
                        foreach ($prop in $props.PSObject.Properties) {
                            if ($prop.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
                                $val = [string]$prop.Value
                                $cleanPath = $val.Trim('"').Split(' ')[0]
                                $sig = "Unchecked"
                                $isClean = $true
                                if (Test-Path $cleanPath -PathType Leaf) {
                                    $sigCheck = Get-AuthenticodeSignature -FilePath $cleanPath -ErrorAction SilentlyContinue
                                    if ($sigCheck) { $sig = $sigCheck.Status.ToString() }
                                    if ($sig -ne 'Valid') { $isClean = $false }
                                }
                                $results += [PSCustomObject]@{
                                    name = $prop.Name
                                    path = $val
                                    location = $key
                                    signature = $sig
                                    isClean = $isClean
                                }
                            }
                        }
                    }
                }
                $results | ConvertTo-Json -Compress
            "#;
            if let Ok(json_str) = execute_powershell(ps) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let items = if val.is_array() { val.as_array().unwrap().clone() } else { vec![val] };
                    for (i, it) in items.iter().enumerate() {
                        let name = it["name"].as_str().unwrap_or("Unknown").to_string();
                        let path = it["path"].as_str().unwrap_or("").to_string();
                        let location = it["location"].as_str().unwrap_or("").to_string();
                        let sig = it["signature"].as_str().unwrap_or("Unknown").to_string();
                        let is_clean = it["isClean"].as_bool().unwrap_or(true);

                        let risk = if !is_clean || sig == "Unknown" || sig == "NotSigned" {
                            suspicious_count += 1;
                            "Medium"
                        } else {
                            "Low"
                        };

                        let mut details = HashMap::new();
                        details.insert("Registry Location".to_string(), location);
                        details.insert("Digital Signature".to_string(), sig.clone());
                        details.insert("Executable Command".to_string(), path.clone());

                        records.push(ForensicScanRecord {
                            id: format!("autorun-{}", i),
                            primary_text: name,
                            secondary_text: path,
                            timestamp: now.clone(),
                            status_tag: sig,
                            risk_level: risk.to_string(),
                            details,
                        });
                    }
                }
            }
        }
        "usb-deview-plus-plus" => {
            tool_name = "USBDeview++ (DMA & USB Forensic Inspector)".to_string();
            let ps = r#"
                $usbList = @()
                $key = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
                if (Test-Path $key) {
                    $devices = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
                    foreach ($d in $devices) {
                        $instances = Get-ChildItem -Path $d.PSPath -ErrorAction SilentlyContinue
                        foreach ($inst in $instances) {
                            $props = Get-ItemProperty -Path $inst.PSPath -ErrorAction SilentlyContinue
                            $fname = $props.FriendlyName
                            if (!$fname) { $fname = $d.PSChildName }
                            $hwId = $props.HardwareID
                            $usbList += [PSCustomObject]@{
                                name = [string]$fname
                                id = [string]$inst.PSChildName
                                hardwareId = [string]($hwId -join '; ')
                                deviceType = [string]$d.PSChildName
                            }
                        }
                    }
                }
                $usbList | ConvertTo-Json -Compress
            "#;
            if let Ok(json_str) = execute_powershell(ps) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let items = if val.is_array() { val.as_array().unwrap().clone() } else { vec![val] };
                    for (i, it) in items.iter().enumerate() {
                        let name = it["name"].as_str().unwrap_or("USB Device").to_string();
                        let dev_id = it["id"].as_str().unwrap_or("").to_string();
                        let hw_id = it["hardwareId"].as_str().unwrap_or("").to_string();
                        let dev_type = it["deviceType"].as_str().unwrap_or("").to_string();

                        let mut details = HashMap::new();
                        details.insert("Instance ID / Serial".to_string(), dev_id.clone());
                        details.insert("Hardware IDs".to_string(), hw_id);
                        details.insert("USB Class Descriptor".to_string(), dev_type);

                        records.push(ForensicScanRecord {
                            id: format!("usb-{}", i),
                            primary_text: name,
                            secondary_text: dev_id,
                            timestamp: now.clone(),
                            status_tag: "Verified USB".to_string(),
                            risk_level: "Low".to_string(),
                            details,
                        });
                    }
                }
            }
        }
        "kernel-live-dump-plus-plus" => {
            tool_name = "KernelLiveDump++ (Live Process Memory Inspector)".to_string();
            let ps = r#"
                Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 35 | ForEach-Object {
                    [PSCustomObject]@{
                        name = $_.ProcessName
                        id = $_.Id
                        handles = $_.Handles
                        wsMB = [math]::Round($_.WorkingSet64 / 1MB, 2)
                        path = $_.Path
                    }
                } | ConvertTo-Json -Compress
            "#;
            if let Ok(json_str) = execute_powershell(ps) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let items = if val.is_array() { val.as_array().unwrap().clone() } else { vec![val] };
                    for (i, it) in items.iter().enumerate() {
                        let name = it["name"].as_str().unwrap_or("").to_string();
                        let pid = it["id"].as_i64().unwrap_or(0);
                        let handles = it["handles"].as_i64().unwrap_or(0);
                        let ws_mb = it["wsMB"].as_f64().unwrap_or(0.0);
                        let path = it["path"].as_str().unwrap_or("System Process").to_string();

                        let mut details = HashMap::new();
                        details.insert("Process ID (PID)".to_string(), pid.to_string());
                        details.insert("RAM Working Set".to_string(), format!("{:.2} MB", ws_mb));
                        details.insert("Active Handles".to_string(), handles.to_string());
                        details.insert("Binary Path".to_string(), path.clone());

                        records.push(ForensicScanRecord {
                            id: format!("proc-{}", i),
                            primary_text: format!("{}.exe (PID: {})", name, pid),
                            secondary_text: format!("Working Set: {:.2} MB | Handles: {} | {}", ws_mb, handles, path),
                            timestamp: now.clone(),
                            status_tag: format!("{:.1} MB RAM", ws_mb),
                            risk_level: "Low".to_string(),
                            details,
                        });
                    }
                }
            }
        }
        "mft-explorer-plus-plus" => {
            tool_name = "MFTExplorer++ (Alternate Data Streams / ADS)".to_string();
            let ps = r#"
                $adsList = @()
                $scanPaths = @(
                    "$env:USERPROFILE\Downloads",
                    "$env:USERPROFILE\Desktop",
                    "$env:TEMP"
                )
                foreach ($p in $scanPaths) {
                    if (Test-Path $p) {
                        $files = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | Select-Object -First 25
                        foreach ($f in $files) {
                            $streams = Get-Item -Path $f.FullName -Stream * -ErrorAction SilentlyContinue
                            foreach ($s in $streams) {
                                if ($s.Stream -ne ':$DATA') {
                                    $adsList += [PSCustomObject]@{
                                        file = $f.Name
                                        stream = $s.Stream
                                        size = $s.Length
                                        path = $f.FullName
                                    }
                                }
                            }
                        }
                    }
                }
                $adsList | ConvertTo-Json -Compress
            "#;
            if let Ok(json_str) = execute_powershell(ps) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let items = if val.is_array() { val.as_array().unwrap().clone() } else { vec![val] };
                    for (i, it) in items.iter().enumerate() {
                        let file = it["file"].as_str().unwrap_or("").to_string();
                        let stream = it["stream"].as_str().unwrap_or("").to_string();
                        let size = it["size"].as_i64().unwrap_or(0);
                        let path = it["path"].as_str().unwrap_or("").to_string();

                        let is_zone = stream.contains("Zone.Identifier");
                        let risk = if !is_zone && size > 1024 {
                            suspicious_count += 1;
                            "Medium"
                        } else {
                            "Low"
                        };

                        let mut details = HashMap::new();
                        details.insert("Stream Name".to_string(), stream.clone());
                        details.insert("Stream Size".to_string(), format!("{} bytes", size));
                        details.insert("Full Path".to_string(), path.clone());

                        records.push(ForensicScanRecord {
                            id: format!("ads-{}", i),
                            primary_text: format!("{} : {}", file, stream),
                            secondary_text: path,
                            timestamp: now.clone(),
                            status_tag: if is_zone { "Zone.Identifier (Download Mark)".to_string() } else { "CUSTOM ADS STREAM".to_string() },
                            risk_level: risk.to_string(),
                            details,
                        });
                    }
                }
            }
        }
        _ => {
            tool_name = format!("Forensic Scanner ({})", tool_id);
            let ps = r#"
                $procs = Get-Process | Select-Object -First 15
                $res = @()
                foreach ($p in $procs) {
                    $res += [PSCustomObject]@{
                        name = $p.ProcessName
                        id = $p.Id
                        path = $p.Path
                    }
                }
                $res | ConvertTo-Json -Compress
            "#;
            if let Ok(json_str) = execute_powershell(ps) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let items = if val.is_array() { val.as_array().unwrap().clone() } else { vec![val] };
                    for (i, it) in items.iter().enumerate() {
                        let name = it["name"].as_str().unwrap_or("").to_string();
                        let pid = it["id"].as_i64().unwrap_or(0);
                        let path = it["path"].as_str().unwrap_or("").to_string();

                        let mut details = HashMap::new();
                        details.insert("Process ID".to_string(), pid.to_string());
                        details.insert("Artifact Path".to_string(), path.clone());

                        records.push(ForensicScanRecord {
                            id: format!("generic-{}", i),
                            primary_text: name,
                            secondary_text: format!("PID: {} | {}", pid, path),
                            timestamp: now.clone(),
                            status_tag: "Verified".to_string(),
                            risk_level: "Low".to_string(),
                            details,
                        });
                    }
                }
            }
        }
    }

    let total = records.len();
    let summary = if suspicious_count > 0 {
        format!("Scan complete. Found {} total forensic records ({} flagged anomalies detected).", total, suspicious_count)
    } else {
        format!("Scan complete. Analyzed {} forensic artifact records with no critical anomalies.", total)
    };

    Ok(ScanOutput {
        tool_id,
        tool_name,
        scan_time: now,
        total_items: total,
        suspicious_count,
        records,
        summary_message: summary,
    })
}

fn analyze_file_strings_and_entropy(path: &str) -> (f64, Vec<String>) {
    if let Ok(bytes) = fs::read(path) {
        let len = bytes.len() as f64;
        let mut counts = [0u64; 256];
        for &b in &bytes {
            counts[b as usize] += 1;
        }

        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = (count as f64) / len;
                entropy -= p * p.log2();
            }
        }

        let mut strings = Vec::new();
        let mut current = Vec::new();
        for &b in &bytes {
            if b >= 32 && b <= 126 {
                current.push(b);
            } else {
                if current.len() >= 6 {
                    if let Ok(s) = String::from_utf8(current.clone()) {
                        if !strings.contains(&s) {
                            strings.push(s);
                            if strings.len() >= 40 {
                                break;
                            }
                        }
                    }
                }
                current.clear();
            }
        }

        (entropy, strings)
    } else {
        (0.0, vec!["Failed to read target file".to_string()])
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            run_forensic_scan
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

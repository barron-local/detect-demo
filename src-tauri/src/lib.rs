use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Default)]
pub struct AppState {
    pub running_processes: Mutex<HashMap<String, u32>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ToolStatus {
    pub tool_id: String,
    pub is_installed: bool,
    pub is_running: bool,
    pub file_path: String,
    pub pid: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct LaunchResponse {
    pub success: bool,
    pub message: String,
    pub pid: Option<u32>,
    pub file_path: String,
}

fn get_tools_dir() -> PathBuf {
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let mut path = PathBuf::from(local_appdata);
        path.push("detect_tools");
        path.push("bin");
        let _ = fs::create_dir_all(&path);
        path
    } else {
        let mut path = std::env::temp_dir();
        path.push("detect_tools");
        path.push("bin");
        let _ = fs::create_dir_all(&path);
        path
    }
}

fn sanitize_filename(name: &str) -> String {
    let safe_name: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '+' { c } else { '_' })
        .collect();
    format!("{}.exe", safe_name)
}

#[tauri::command]
fn get_tool_status(tool_id: String, tool_name: String, state: State<'_, AppState>) -> ToolStatus {
    let tools_dir = get_tools_dir();
    let file_name = sanitize_filename(&tool_name);
    let target_file = tools_dir.join(&file_name);
    let is_installed = target_file.exists() && target_file.metadata().map(|m| m.len() > 0).unwrap_or(false);

    let map = state.running_processes.lock().unwrap();
    let pid = map.get(&tool_id).copied();
    let is_running = pid.is_some();

    ToolStatus {
        tool_id,
        is_installed,
        is_running,
        file_path: target_file.to_string_lossy().to_string(),
        pid,
    }
}

#[tauri::command]
fn launch_tool(
    tool_id: String,
    tool_name: String,
    download_url: String,
    state: State<'_, AppState>,
) -> Result<LaunchResponse, String> {
    let tools_dir = get_tools_dir();
    let file_name = sanitize_filename(&tool_name);
    let target_file = tools_dir.join(&file_name);
    let target_path_str = target_file.to_string_lossy().to_string();

    let is_installed = target_file.exists() && target_file.metadata().map(|m| m.len() > 0).unwrap_or(false);

    if !is_installed {
        let dl_cmd = Command::new("curl.exe")
            .args(&["-L", "-k", "-s", "-o", &target_path_str, &download_url])
            .output();

        let download_success = match dl_cmd {
            Ok(out) => out.status.success() && target_file.exists() && target_file.metadata().map(|m| m.len() > 0).unwrap_or(false),
            Err(_) => false,
        };

        if !download_success {
            let ps_script = format!(
                "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing",
                download_url, target_path_str
            );
            let ps_out = Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_script])
                .output();

            let ps_success = match ps_out {
                Ok(out) => out.status.success() && target_file.exists() && target_file.metadata().map(|m| m.len() > 0).unwrap_or(false),
                Err(_) => false,
            };

            if !ps_success {
                return Err(format!(
                    "Tool executable could not be fetched automatically. Please ensure network access to {}",
                    download_url
                ));
            }
        }
    }

    #[cfg(target_os = "windows")]
    let spawn_result = {
        let ps_launch = format!("Start-Process -FilePath '{}' -PassThru | Select-Object -ExpandProperty Id", target_path_str);
        Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_launch])
            .output()
    };

    #[cfg(not(target_os = "windows"))]
    let spawn_result = Command::new(&target_file).spawn();

    #[cfg(target_os = "windows")]
    match spawn_result {
        Ok(out) => {
            let stdout_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let pid = stdout_str.parse::<u32>().ok();
            if let Some(p) = pid {
                let mut map = state.running_processes.lock().unwrap();
                map.insert(tool_id.clone(), p);
            }
            Ok(LaunchResponse {
                success: true,
                message: format!("{} successfully launched (PID: {:?})", tool_name, pid),
                pid,
                file_path: target_path_str,
            })
        }
        Err(e) => Err(format!("Failed to execute process: {}", e)),
    }

    #[cfg(not(target_os = "windows"))]
    match spawn_result {
        Ok(child) => {
            let pid = child.id();
            let mut map = state.running_processes.lock().unwrap();
            map.insert(tool_id.clone(), pid);
            Ok(LaunchResponse {
                success: true,
                message: format!("{} launched successfully with PID {}", tool_name, pid),
                pid: Some(pid),
                file_path: target_path_str,
            })
        }
        Err(e) => Err(format!("Failed to execute binary: {}", e)),
    }
}

#[tauri::command]
fn kill_tool(tool_id: String, state: State<'_, AppState>) -> Result<bool, String> {
    let mut map = state.running_processes.lock().unwrap();
    if let Some(pid) = map.remove(&tool_id) {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("taskkill")
                .args(&["/F", "/PID", &pid.to_string()])
                .output();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = Command::new("kill")
                .args(&["-9", &pid.to_string()])
                .output();
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
fn open_tools_folder() -> Result<(), String> {
    let tools_dir = get_tools_dir();
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("explorer").arg(&tools_dir).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(&tools_dir).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(&tools_dir).spawn();
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            get_tool_status,
            launch_tool,
            kill_tool,
            open_tools_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

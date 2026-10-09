import { invoke } from "@tauri-apps/api/core";
import { ForensicTool } from "../data/toolsData";

export interface ToolStatusResponse {
  tool_id: string;
  is_installed: boolean;
  is_running: boolean;
  file_path: string;
  pid: number | null;
}

export interface LaunchResponse {
  success: boolean;
  message: string;
  pid: number | null;
  file_path: string;
}

export async function launchTool(tool: ForensicTool): Promise<LaunchResponse> {
  try {
    return await invoke<LaunchResponse>("launch_tool", {
      toolId: tool.id,
      toolName: tool.name,
      downloadUrl: tool.downloadUrl,
    });
  } catch (error) {
    const errorMsg = typeof error === "string" ? error : JSON.stringify(error);
    return {
      success: false,
      message: errorMsg,
      pid: null,
      file_path: "",
    };
  }
}

export async function getToolStatus(tool: ForensicTool): Promise<ToolStatusResponse> {
  try {
    return await invoke<ToolStatusResponse>("get_tool_status", {
      toolId: tool.id,
      toolName: tool.name,
    });
  } catch {
    return {
      tool_id: tool.id,
      is_installed: false,
      is_running: false,
      file_path: "",
      pid: null,
    };
  }
}

export async function killTool(toolId: string): Promise<boolean> {
  try {
    return await invoke<boolean>("kill_tool", { toolId });
  } catch {
    return false;
  }
}

export async function openToolsFolder(): Promise<void> {
  try {
    await invoke("open_tools_folder");
  } catch {
  }
}

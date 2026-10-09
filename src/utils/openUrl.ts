export async function openExternalLink(url: string) {
  try {
    // Attempt Tauri opener plugin if available
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    if (typeof openUrl === "function") {
      await openUrl(url);
      return;
    }
  } catch {
    // Fallback to browser window.open
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

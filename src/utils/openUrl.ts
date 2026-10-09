export async function openExternalLink(url: string) {
  try {
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    if (typeof openUrl === "function") {
      await openUrl(url);
      return;
    }
  } catch {
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

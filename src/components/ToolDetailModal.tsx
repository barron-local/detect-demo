import React, { useEffect, useState } from "react";
import { ForensicTool } from "../data/toolsData";
import { ToolIcon } from "./ToolIcon";
import { launchTool, killTool, openToolsFolder } from "../services/toolRunner";
import {
  X,
  Play,
  Square,
  Loader2,
  FolderOpen,
  Copy,
  Check,
  Shield,
  Layers,
  Terminal,
  Database,
  Sparkles,
} from "lucide-react";

interface ToolDetailModalProps {
  tool: ForensicTool | null;
  onClose: () => void;
  isRunning?: boolean;
  onStatusChange?: (toolId: string, running: boolean, msg?: string) => void;
}

export const ToolDetailModal: React.FC<ToolDetailModalProps> = ({
  tool,
  onClose,
  isRunning = false,
  onStatusChange,
}) => {
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [copiedLink, setCopiedLink] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (tool) {
      document.body.style.overflow = "hidden";
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => {
      document.body.style.overflow = "auto";
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [tool, onClose]);

  if (!tool) return null;

  const handleLaunch = async () => {
    if (loading) return;

    if (isRunning) {
      setLoading(true);
      await killTool(tool.id);
      setLoading(false);
      onStatusChange?.(tool.id, false, "Process stopped");
      setStatusMessage("Tool process terminated");
      return;
    }

    setLoading(true);
    setStatusMessage("Checking binary & launching process...");
    const res = await launchTool(tool);
    setLoading(false);

    if (res.success) {
      onStatusChange?.(tool.id, true, res.message);
      setStatusMessage(res.message);
    } else {
      onStatusChange?.(tool.id, false, res.message);
      setStatusMessage(`Launch failed: ${res.message}`);
    }
  };

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(tool.downloadUrl);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    } catch {
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-container" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-row">
            <div className="modal-icon-badge">
              <ToolIcon name={tool.iconName} size={28} className="tool-icon-svg" />
            </div>
            <div>
              <div className="modal-title-wrap">
                <h2 className="modal-title">{tool.name}</h2>
                <span className="modal-version-tag">{tool.version}</span>
                {isRunning ? (
                  <span className="badge-pill badge-running">
                    <span className="pulse-dot-mini" /> RUNNING
                  </span>
                ) : (
                  tool.badge && (
                    <span className={`badge-pill badge-${tool.badge.toLowerCase()}`}>
                      {tool.badge}
                    </span>
                  )
                )}
              </div>
              <p className="modal-category">{tool.category}</p>
            </div>
          </div>
          <button
            className="modal-close-btn"
            onClick={onClose}
            title="Close (Esc)"
            aria-label="Close"
          >
            <X size={20} />
          </button>
        </div>

        <div className="modal-body">
          <div className="modal-tagline-box">
            <Sparkles size={18} className="text-accent" />
            <p className="modal-tagline">{tool.tagline}</p>
          </div>

          <div className="modal-section">
            <h3 className="modal-section-title">
              <Layers size={16} /> Overview & Purpose
            </h3>
            <p className="modal-description">{tool.description}</p>
          </div>

          <div className="modal-section">
            <h3 className="modal-section-title">
              <Database size={16} /> Target Forensic Artifacts
            </h3>
            <div className="modal-artifact-box">
              <code className="modal-artifact-code">{tool.targetArtifact}</code>
            </div>
          </div>

          <div className="modal-section">
            <h3 className="modal-section-title">
              <Shield size={16} /> Key Capabilities & Forensic Engine
            </h3>
            <div className="modal-features-grid">
              {tool.features.map((feat, idx) => (
                <div key={idx} className="modal-feature-item">
                  <div className="feature-dot">
                    <Check size={12} />
                  </div>
                  <span>{feat}</span>
                </div>
              ))}
            </div>
          </div>

          {statusMessage && (
            <div className="modal-status-terminal">
              <div className="terminal-header">
                <Terminal size={14} />
                <span>Execution Status</span>
              </div>
              <div className="terminal-body">
                <code>{statusMessage}</code>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button
            className="btn-secondary"
            onClick={() => openToolsFolder()}
            title="Open local tools cache folder"
          >
            <FolderOpen size={16} />
            <span>Tools Folder</span>
          </button>

          <button
            className="btn-secondary"
            onClick={handleCopyLink}
          >
            {copiedLink ? (
              <>
                <Check size={16} className="text-emerald" /> Copied
              </>
            ) : (
              <>
                <Copy size={16} /> URL
              </>
            )}
          </button>

          <button
            className={`btn-primary ${isRunning ? "btn-stop" : ""}`}
            onClick={handleLaunch}
            disabled={loading}
          >
            {loading ? (
              <>
                <Loader2 size={16} className="spin-icon" />
                <span>Processing...</span>
              </>
            ) : isRunning ? (
              <>
                <Square size={16} />
                <span>Stop {tool.name}</span>
              </>
            ) : (
              <>
                <Play size={16} fill="currentColor" />
                <span>Run {tool.name}</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

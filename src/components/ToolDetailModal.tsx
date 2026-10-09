import React, { useEffect, useState } from "react";
import { ForensicTool } from "../data/toolsData";
import { ToolIcon } from "./ToolIcon";
import { openExternalLink } from "../utils/openUrl";
import {
  X,
  Download,
  Copy,
  Check,
  ExternalLink,
  Shield,
  Layers,
  Terminal,
  Database,
  Sparkles,
} from "lucide-react";

interface ToolDetailModalProps {
  tool: ForensicTool | null;
  onClose: () => void;
}

export const ToolDetailModal: React.FC<ToolDetailModalProps> = ({
  tool,
  onClose,
}) => {
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState(false);

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

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(tool.downloadUrl);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2000);
    } catch {
    }
  };

  const powershellCommand = `Invoke-WebRequest -Uri "${tool.downloadUrl}" -OutFile "${tool.name}.exe"`;

  const handleCopyCommand = async () => {
    try {
      await navigator.clipboard.writeText(powershellCommand);
      setCopiedCommand(true);
      setTimeout(() => setCopiedCommand(false), 2000);
    } catch {
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true">
      <div
        className="modal-container"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div className="modal-title-row">
            <div className="modal-icon-badge">
              <ToolIcon name={tool.iconName} size={28} className="tool-icon-svg" />
            </div>
            <div>
              <div className="modal-title-wrap">
                <h2 className="modal-title">{tool.name}</h2>
                <span className="modal-version-tag">{tool.version}</span>
                {tool.badge && (
                  <span className={`badge-pill badge-${tool.badge.toLowerCase()}`}>
                    {tool.badge}
                  </span>
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

          <div className="modal-section">
            <div className="modal-cli-header">
              <h3 className="modal-section-title">
                <Terminal size={16} /> PowerShell Quick Download
              </h3>
              <button
                className="cli-copy-btn"
                onClick={handleCopyCommand}
                title="Copy Command"
              >
                {copiedCommand ? (
                  <>
                    <Check size={14} className="text-emerald" /> Copied
                  </>
                ) : (
                  <>
                    <Copy size={14} /> Copy Command
                  </>
                )}
              </button>
            </div>
            <pre className="modal-cli-box">
              <code>{powershellCommand}</code>
            </pre>
          </div>
        </div>

        <div className="modal-footer">
          <button
            className="btn-secondary"
            onClick={handleCopyLink}
          >
            {copiedLink ? (
              <>
                <Check size={16} className="text-emerald" /> Link Copied
              </>
            ) : (
              <>
                <Copy size={16} /> Copy URL
              </>
            )}
          </button>
          <button
            className="btn-primary"
            onClick={() => openExternalLink(tool.downloadUrl)}
          >
            <Download size={16} />
            <span>Download {tool.name}</span>
            <ExternalLink size={14} className="opacity-70" />
          </button>
        </div>
      </div>
    </div>
  );
};

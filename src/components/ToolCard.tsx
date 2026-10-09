import React, { useState } from "react";
import { ForensicTool } from "../data/toolsData";
import { ToolIcon } from "./ToolIcon";
import { openExternalLink } from "../utils/openUrl";
import {
  Download,
  Copy,
  Check,
  ExternalLink,
  ChevronRight,
  Database,
} from "lucide-react";

interface ToolCardProps {
  tool: ForensicTool;
  onSelect: (tool: ForensicTool) => void;
}

export const ToolCard: React.FC<ToolCardProps> = ({ tool, onSelect }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(tool.downloadUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
    }
  };

  const handleDownload = (e: React.MouseEvent) => {
    e.stopPropagation();
    openExternalLink(tool.downloadUrl);
  };

  return (
    <article
      className="tool-card"
      onClick={() => onSelect(tool)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(tool);
        }
      }}
    >
      <div className="tool-card-glow" />

      <div className="card-top">
        <div className="card-icon-container">
          <ToolIcon name={tool.iconName} size={22} className="card-icon-svg" />
        </div>

        <div className="card-meta-tags">
          {tool.badge && (
            <span className={`badge-pill badge-${tool.badge.toLowerCase()}`}>
              {tool.badge}
            </span>
          )}
          <span className="version-pill">{tool.version}</span>
        </div>
      </div>

      <div className="card-title-block">
        <div className="category-micro">{tool.category}</div>
        <h3 className="card-title">{tool.name}</h3>
        <p className="card-tagline">{tool.tagline}</p>
      </div>

      <div className="card-artifact-row">
        <Database size={13} className="text-muted" />
        <span className="artifact-label">Target:</span>
        <span className="artifact-code">{tool.targetArtifact}</span>
      </div>

      <div className="card-highlights">
        {tool.highlights.map((item, idx) => (
          <span key={idx} className="highlight-tag">
            {item}
          </span>
        ))}
      </div>

      <p className="card-description-excerpt">{tool.description}</p>

      <div className="card-actions" onClick={(e) => e.stopPropagation()}>
        <button
          className="btn-card-action btn-inspect"
          onClick={() => onSelect(tool)}
          title="Inspect Tool Specifications"
        >
          <span>Inspect</span>
          <ChevronRight size={14} />
        </button>

        <div className="card-action-group">
          <button
            className="btn-icon-action"
            onClick={handleCopy}
            title={copied ? "Link Copied!" : "Copy Download Link"}
          >
            {copied ? (
              <Check size={15} className="text-emerald" />
            ) : (
              <Copy size={15} />
            )}
          </button>

          <button
            className="btn-card-download"
            onClick={handleDownload}
            title={`Download ${tool.name}`}
          >
            <Download size={14} />
            <span>Download</span>
            <ExternalLink size={12} className="opacity-70" />
          </button>
        </div>
      </div>
    </article>
  );
};

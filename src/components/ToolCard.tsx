import React, { useState } from "react";
import { ForensicTool } from "../data/toolsData";
import { ToolIcon } from "./ToolIcon";
import { launchTool, killTool } from "../services/toolRunner";
import {
  Play,
  Square,
  Loader2,
  ChevronRight,
  Database,
} from "lucide-react";

interface ToolCardProps {
  tool: ForensicTool;
  onSelect: (tool: ForensicTool) => void;
  isRunning?: boolean;
  onStatusChange?: (toolId: string, running: boolean, msg?: string) => void;
}

export const ToolCard: React.FC<ToolCardProps> = ({
  tool,
  onSelect,
  isRunning = false,
  onStatusChange,
}) => {
  const [loading, setLoading] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  const handleLaunch = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (loading) return;

    if (isRunning) {
      setLoading(true);
      await killTool(tool.id);
      setLoading(false);
      onStatusChange?.(tool.id, false, "Process stopped");
      setFeedback("Stopped");
      setTimeout(() => setFeedback(null), 2500);
      return;
    }

    setLoading(true);
    setFeedback("Preparing & Launching...");
    const res = await launchTool(tool);
    setLoading(false);

    if (res.success) {
      onStatusChange?.(tool.id, true, res.message);
      setFeedback("Running");
      setTimeout(() => setFeedback(null), 3000);
    } else {
      onStatusChange?.(tool.id, false, res.message);
      setFeedback("Failed to launch");
      setTimeout(() => setFeedback(null), 3500);
    }
  };

  return (
    <article
      className={`tool-card ${isRunning ? "card-running" : ""}`}
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
      <div className={`tool-card-glow ${isRunning ? "glow-active" : ""}`} />

      <div className="card-top">
        <div className="card-icon-container">
          <ToolIcon name={tool.iconName} size={22} className="card-icon-svg" />
        </div>

        <div className="card-meta-tags">
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

      {feedback && (
        <div className={`card-feedback-banner ${feedback === "Running" ? "fb-success" : ""}`}>
          <span>{feedback}</span>
        </div>
      )}

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
            className={`btn-card-run ${isRunning ? "btn-stop" : ""}`}
            onClick={handleLaunch}
            disabled={loading}
            title={isRunning ? `Stop ${tool.name}` : `Run ${tool.name} directly`}
          >
            {loading ? (
              <>
                <Loader2 size={14} className="spin-icon" />
                <span>Launching...</span>
              </>
            ) : isRunning ? (
              <>
                <Square size={13} />
                <span>Stop Tool</span>
              </>
            ) : (
              <>
                <Play size={13} fill="currentColor" />
                <span>Run Tool</span>
              </>
            )}
          </button>
        </div>
      </div>
    </article>
  );
};

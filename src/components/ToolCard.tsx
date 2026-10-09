import React from "react";
import { ForensicTool } from "../data/toolsData";
import { ToolIcon } from "./ToolIcon";
import { Activity, Info } from "lucide-react";

interface ToolCardProps {
  tool: ForensicTool;
  onSelect: (tool: ForensicTool) => void;
  onOpenScanner: (tool: ForensicTool) => void;
}

export const ToolCard: React.FC<ToolCardProps> = ({
  tool,
  onSelect,
  onOpenScanner,
}) => {
  return (
    <article
      className="tool-card"
      onClick={() => onOpenScanner(tool)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpenScanner(tool);
        }
      }}
    >
      <div className="tool-card-glow" />

      <div className="card-header-clean">
        <div className="card-icon-container">
          <ToolIcon name={tool.iconName} size={20} className="card-icon-svg" />
        </div>

        <div className="card-title-group">
          <h3 className="card-title">{tool.name}</h3>
          <span className="card-category-text">{tool.category}</span>
        </div>
      </div>

      <p className="card-tagline">{tool.tagline}</p>

      <div className="card-target-pill">
        <span className="target-pill-label">Target:</span>
        <code className="target-pill-code">{tool.targetArtifact}</code>
      </div>

      <div className="card-actions" onClick={(e) => e.stopPropagation()}>
        <button
          className="btn-card-specs"
          onClick={() => onSelect(tool)}
          title="View Specifications"
        >
          <Info size={13} />
          <span>Specs</span>
        </button>

        <button
          className="btn-card-run"
          onClick={() => onOpenScanner(tool)}
          title={`Analyze ${tool.name}`}
        >
          <Activity size={13} />
          <span>Analyze</span>
        </button>
      </div>
    </article>
  );
};

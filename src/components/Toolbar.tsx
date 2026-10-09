import React from "react";
import { SlidersHorizontal, Grid, List, Zap } from "lucide-react";

interface ToolbarProps {
  sortBy: "name" | "category" | "badge";
  onSortChange: (sort: "name" | "category" | "badge") => void;
  viewMode: "grid" | "list";
  onViewModeChange: (mode: "grid" | "list") => void;
  totalFiltered: number;
  onOpenFullAudit?: () => void;
}

export const Toolbar: React.FC<ToolbarProps> = ({
  sortBy,
  onSortChange,
  viewMode,
  onViewModeChange,
  totalFiltered,
  onOpenFullAudit,
}) => {
  return (
    <div className="toolbar-container">
      <div className="toolbar-left">
        <span className="toolbar-count-badge">{totalFiltered} modules</span>
        {onOpenFullAudit && (
          <button
            type="button"
            className="toolbar-audit-btn"
            onClick={onOpenFullAudit}
            title="Scan and aggregate live results for all 17 tools"
          >
            <Zap size={13} className="text-cyan" />
            <span>Audit All 17 Tools</span>
          </button>
        )}
      </div>

      <div className="toolbar-controls">
        <div className="sort-wrapper">
          <SlidersHorizontal size={13} className="text-muted" />
          <select
            className="sort-select"
            value={sortBy}
            onChange={(e) =>
              onSortChange(e.target.value as "name" | "category" | "badge")
            }
          >
            <option value="name">Sort by Name</option>
            <option value="category">Sort by Category</option>
            <option value="badge">Featured First</option>
          </select>
        </div>

        <div className="view-mode-toggle">
          <button
            type="button"
            className={`view-btn ${viewMode === "grid" ? "active" : ""}`}
            onClick={() => onViewModeChange("grid")}
            title="Grid View"
          >
            <Grid size={14} />
          </button>
          <button
            type="button"
            className={`view-btn ${viewMode === "list" ? "active" : ""}`}
            onClick={() => onViewModeChange("list")}
            title="List View"
          >
            <List size={14} />
          </button>
        </div>
      </div>
    </div>
  );
};

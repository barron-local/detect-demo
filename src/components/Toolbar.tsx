import React from "react";
import { Filter, SlidersHorizontal, Grid, List, X } from "lucide-react";

interface ToolbarProps {
  sortBy: "name" | "category" | "badge";
  onSortChange: (sort: "name" | "category" | "badge") => void;
  viewMode: "grid" | "list";
  onViewModeChange: (mode: "grid" | "list") => void;
  activeFeatureFilter: string | null;
  onFeatureFilterChange: (feature: string | null) => void;
  totalFiltered: number;
}

const FEATURE_SHORTCUTS = [
  "USN Journal",
  "YARA",
  "VirusTotal",
  "Bypass",
  "RAM Dump",
  "DMA",
];

export const Toolbar: React.FC<ToolbarProps> = ({
  sortBy,
  onSortChange,
  viewMode,
  onViewModeChange,
  activeFeatureFilter,
  onFeatureFilterChange,
  totalFiltered,
}) => {
  return (
    <div className="toolbar-container">
      <div className="toolbar-tags">
        <span className="toolbar-tag-label">
          <Filter size={13} /> Quick Filter:
        </span>
        {FEATURE_SHORTCUTS.map((tag) => {
          const isActive = activeFeatureFilter === tag;
          return (
            <button
              key={tag}
              className={`filter-tag-chip ${isActive ? "active" : ""}`}
              onClick={() => onFeatureFilterChange(isActive ? null : tag)}
            >
              <span>{tag}</span>
              {isActive && <X size={12} className="tag-clear-icon" />}
            </button>
          );
        })}
      </div>

      <div className="toolbar-controls">
        <div className="sort-wrapper">
          <span className="category-badge-count">{totalFiltered}</span>
          <SlidersHorizontal size={14} className="text-muted" />
          <span className="sort-label">Sort:</span>
          <select
            className="sort-select"
            value={sortBy}
            onChange={(e) =>
              onSortChange(e.target.value as "name" | "category" | "badge")
            }
          >
            <option value="name">Name (A-Z)</option>
            <option value="category">Category</option>
            <option value="badge">Featured First</option>
          </select>
        </div>

        <div className="view-mode-toggle">
          <button
            className={`view-btn ${viewMode === "grid" ? "active" : ""}`}
            onClick={() => onViewModeChange("grid")}
            title="Grid View"
          >
            <Grid size={15} />
          </button>
          <button
            className={`view-btn ${viewMode === "list" ? "active" : ""}`}
            onClick={() => onViewModeChange("list")}
            title="Compact List View"
          >
            <List size={15} />
          </button>
        </div>
      </div>
    </div>
  );
};

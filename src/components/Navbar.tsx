import React from "react";
import { Shield, FolderOpen, Search } from "lucide-react";
import { openToolsFolder } from "../services/toolRunner";

interface NavbarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  toolCount: number;
  runningCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  searchQuery,
  onSearchChange,
  toolCount,
  runningCount,
}) => {
  return (
    <header className="site-header">
      <div className="header-container">
        <div className="brand-group" onClick={() => onSearchChange("")}>
          <div className="brand-logo-glow">
            <Shield className="brand-icon" size={22} />
          </div>
          <div className="brand-text-block">
            <div className="brand-title-row">
              <span className="brand-name">DETECT<span className="brand-accent">.AC</span></span>
              <span className="brand-badge">RUNNER</span>
            </div>
            <span className="brand-sub">Native Windows Forensic Launcher</span>
          </div>
        </div>

        <div className="nav-search-wrap">
          <Search size={16} className="nav-search-icon" />
          <input
            type="text"
            className="nav-search-input"
            placeholder="Search tools, artifacts ($MFT, BAM, YARA, RAM)..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
          />
          {searchQuery && (
            <button
              className="search-clear-btn"
              onClick={() => onSearchChange("")}
            >
              ×
            </button>
          )}
          <span className="search-shortcut">/</span>
        </div>

        <div className="nav-actions">
          {runningCount > 0 ? (
            <div className="live-status-pill pill-running">
              <span className="pulse-dot-mini" />
              <span className="status-text">{runningCount} Running</span>
            </div>
          ) : (
            <div className="live-status-pill">
              <span className="pulse-dot" />
              <span className="status-text">{toolCount} Ready to Run</span>
            </div>
          )}

          <button
            className="nav-link-btn"
            onClick={() => openToolsFolder()}
            title="Open local tools directory in Explorer"
          >
            <FolderOpen size={14} />
            <span>Tools Directory</span>
          </button>
        </div>
      </div>
    </header>
  );
};

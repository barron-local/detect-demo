import React from "react";
import { Shield, ExternalLink, Search } from "lucide-react";
import { openExternalLink } from "../utils/openUrl";

interface NavbarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  toolCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  searchQuery,
  onSearchChange,
  toolCount,
}) => {
  return (
    <header className="site-header">
      <div className="header-container">
        {/* Brand */}
        <div className="brand-group" onClick={() => onSearchChange("")}>
          <div className="brand-logo-glow">
            <Shield className="brand-icon" size={22} />
          </div>
          <div className="brand-text-block">
            <div className="brand-title-row">
              <span className="brand-name">DETECT<span className="brand-accent">.AC</span></span>
              <span className="brand-badge">SUITE</span>
            </div>
            <span className="brand-sub">Windows Forensics & Anti-Cheat Analysis</span>
          </div>
        </div>

        {/* Global Search Input in Nav */}
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

        {/* Status and Links */}
        <div className="nav-actions">
          <div className="live-status-pill">
            <span className="pulse-dot" />
            <span className="status-text">{toolCount} Tools Active</span>
          </div>

          <button
            className="nav-link-btn"
            onClick={() => openExternalLink("https://detect.ac")}
            title="Visit detect.ac official website"
          >
            <span>detect.ac</span>
            <ExternalLink size={13} />
          </button>
        </div>
      </div>
    </header>
  );
};

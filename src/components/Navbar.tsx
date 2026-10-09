import React from "react";
import { Shield, Search } from "lucide-react";

interface NavbarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  searchQuery,
  onSearchChange,
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
              <span className="brand-badge">NATIVE SUITE</span>
            </div>
            <span className="brand-sub">Standalone Forensic & Anti-Cheat Analysis Engine</span>
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
      </div>
    </header>
  );
};

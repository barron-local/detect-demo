import React from "react";
import { Shield, Search, FlaskConical, Zap } from "lucide-react";

interface NavbarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onOpenDiagnostics: () => void;
  onOpenFullAudit: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  searchQuery,
  onSearchChange,
  onOpenDiagnostics,
  onOpenFullAudit,
}) => {
  return (
    <header className="site-header">
      <div className="header-container">
        <div className="brand-group" onClick={() => onSearchChange("")}>
          <div className="brand-logo-glow">
            <Shield className="brand-icon" size={22} />
          </div>
          <div className="brand-text-block">
            <span className="brand-name">DETECT<span className="brand-accent">.DEMO</span></span>
          </div>
        </div>

        <div className="nav-right-actions">
          <button
            type="button"
            className="btn-nav-audit"
            onClick={onOpenFullAudit}
            title="Execute Full 17-Module System Forensic Audit"
          >
            <Zap size={14} className="text-cyan" />
            <span>Run All 17 Tools</span>
          </button>

          <button
            type="button"
            className="btn-nav-diagnostics"
            onClick={onOpenDiagnostics}
            title="Open Detection Test Suite & Heuristic QA Lab"
          >
            <FlaskConical size={14} className="text-emerald" />
            <span>Test Suite</span>
          </button>

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
                type="button"
                className="search-clear-btn"
                onClick={() => onSearchChange("")}
              >
                ×
              </button>
            )}
            <span className="search-shortcut">/</span>
          </div>
        </div>
      </div>
    </header>
  );
};

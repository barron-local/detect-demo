import React, { useState, useEffect } from "react";
import { ForensicTool } from "../data/toolsData";
import { ToolIcon } from "./ToolIcon";
import { runForensicScan, ScanOutput } from "../services/forensicScanner";
import {
  X,
  RefreshCw,
  Search,
  Copy,
  Check,
  Activity,
  ChevronDown,
  ChevronRight,
  Download,
} from "lucide-react";

interface ScanModalProps {
  tool: ForensicTool | null;
  onClose: () => void;
}

export const ScanModal: React.FC<ScanModalProps> = ({ tool, onClose }) => {
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanOutput | null>(null);
  const [filterQuery, setFilterQuery] = useState("");
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState(false);
  const [customTarget, setCustomTarget] = useState("");

  const executeScan = async (target?: string) => {
    if (!tool) return;
    setLoading(true);
    setScanResult(null);
    setSelectedRecordId(null);
    try {
      const output = await runForensicScan(tool.id, target);
      setScanResult(output);
    } catch {
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (tool) {
      document.body.style.overflow = "hidden";
      window.addEventListener("keydown", handleKeyDown);
      executeScan();
    }
    return () => {
      document.body.style.overflow = "auto";
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [tool]);

  if (!tool) return null;

  const filteredRecords = (scanResult?.records || []).filter((r) => {
    if (!filterQuery.trim()) return true;
    const q = filterQuery.toLowerCase();
    return (
      r.primary_text.toLowerCase().includes(q) ||
      r.secondary_text.toLowerCase().includes(q) ||
      r.status_tag.toLowerCase().includes(q) ||
      r.risk_level.toLowerCase().includes(q)
    );
  });

  const handleCopyReport = async () => {
    if (!scanResult) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(scanResult, null, 2));
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2000);
    } catch {
    }
  };

  const handleExportJSON = () => {
    if (!scanResult) return;
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${tool.id}-forensic-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-container scan-modal-container" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-row">
            <div className="modal-icon-badge">
              <ToolIcon name={tool.iconName} size={28} className="tool-icon-svg" />
            </div>
            <div>
              <div className="modal-title-wrap">
                <h2 className="modal-title">{tool.name}</h2>
              </div>
              <p className="modal-category">Target: {tool.targetArtifact}</p>
            </div>
          </div>

          <div className="modal-header-actions">
            <button
              className="btn-icon-action"
              onClick={() => executeScan(customTarget)}
              disabled={loading}
              title="Re-run Scanner"
            >
              <RefreshCw size={16} className={loading ? "spin-icon" : ""} />
            </button>
            <button
              className="modal-close-btn"
              onClick={onClose}
              title="Close (Esc)"
              aria-label="Close"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        <div className="scan-modal-body">
          {tool.id === "string-explorer-plus-plus" && (
            <div className="scan-custom-target-bar">
              <span className="target-bar-label">Target File:</span>
              <input
                type="text"
                className="target-bar-input"
                placeholder="C:\Windows\explorer.exe"
                value={customTarget}
                onChange={(e) => setCustomTarget(e.target.value)}
              />
              <button
                className="btn-target-scan"
                onClick={() => executeScan(customTarget)}
                disabled={loading}
              >
                Inspect Binary
              </button>
            </div>
          )}

          {loading ? (
            <div className="scan-loading-box">

              <h4 className="scan-loading-title">Scanning Windows Forensic Artifacts...</h4>
              <p className="scan-loading-subtitle">
                Querying {tool.targetArtifact} directly via native forensic engine
              </p>
              <div className="scan-progress-bar-container">
                <div className="scan-progress-bar-indeterminate" />
              </div>
            </div>
          ) : scanResult ? (
            <div className="scan-results-wrapper">
              <div className="scan-summary-banner">
                <div className="summary-stat-group">
                  <div className="stat-pill">
                    <span className="stat-num">{scanResult.total_items}</span>
                    <span className="stat-txt">Items Scanned</span>
                  </div>
                  <div className={`stat-pill ${scanResult.suspicious_count > 0 ? "stat-warn" : "stat-ok"}`}>
                    <span className="stat-num">{scanResult.suspicious_count}</span>
                    <span className="stat-txt">Flagged Anomalies</span>
                  </div>
                </div>
                <div className="summary-msg">
                  <span>{scanResult.summary_message}</span>
                </div>
              </div>

              <div className="scan-table-filter-bar">
                <div className="table-search-wrap">
                  <Search size={14} className="text-muted" />
                  <input
                    type="text"
                    className="table-search-input"
                    placeholder="Filter scanned records (name, hash, path, flag)..."
                    value={filterQuery}
                    onChange={(e) => setFilterQuery(e.target.value)}
                  />
                  {filterQuery && (
                    <button className="clear-filter-btn" onClick={() => setFilterQuery("")}>
                      ×
                    </button>
                  )}
                </div>
                <span className="table-count-label">
                  Showing {filteredRecords.length} of {scanResult.records.length}
                </span>
              </div>

              <div className="scan-records-table-container">
                <table className="scan-records-table">
                  <thead>
                    <tr>
                      <th>Artifact / Identifier</th>
                      <th>Status / Signature</th>
                      <th>Risk</th>
                      <th>Timestamp</th>
                      <th>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRecords.length > 0 ? (
                      filteredRecords.map((r) => {
                        const isExpanded = selectedRecordId === r.id;
                        return (
                          <React.Fragment key={r.id}>
                            <tr
                              className={`record-row ${isExpanded ? "row-expanded" : ""} ${
                                r.status_tag.includes("PINK") ? "row-pink" : ""
                              }`}
                              onClick={() => setSelectedRecordId(isExpanded ? null : r.id)}
                            >
                              <td className="cell-primary">
                                <div className="primary-title">{r.primary_text}</div>
                                <div className="secondary-subtitle">{r.secondary_text}</div>
                              </td>
                              <td>
                                <span className={`status-chip ${getStatusClass(r.status_tag)}`}>
                                  {r.status_tag}
                                </span>
                              </td>
                              <td>
                                <span className={`risk-chip risk-${r.risk_level.toLowerCase()}`}>
                                  {r.risk_level}
                                </span>
                              </td>
                              <td className="cell-timestamp">{r.timestamp}</td>
                              <td className="cell-expand">
                                {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr className="record-details-row">
                                <td colSpan={5}>
                                  <div className="expanded-details-box">
                                    <div className="details-grid">
                                      {Object.entries(r.details).map(([k, v]) => (
                                        <div key={k} className="detail-field">
                                          <span className="field-key">{k}:</span>
                                          <code className="field-val">{v}</code>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })
                    ) : (
                      <tr>
                        <td colSpan={5} className="no-records-cell">
                          No matching records found for "{filterQuery}"
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
        </div>

        <div className="modal-footer">
          <button className="btn-secondary" onClick={handleCopyReport}>
            {copiedReport ? (
              <>
                <Check size={16} className="text-emerald" /> Report Copied
              </>
            ) : (
              <>
                <Copy size={16} /> Copy JSON
              </>
            )}
          </button>
          <button className="btn-secondary" onClick={handleExportJSON}>
            <Download size={16} /> Export File
          </button>
          <button
            className="btn-primary"
            onClick={() => executeScan(customTarget)}
            disabled={loading}
          >
            <RefreshCw size={16} className={loading ? "spin-icon" : ""} />
            <span>Re-Scan Artifacts</span>
          </button>
        </div>
      </div>
    </div>
  );
};

function getStatusClass(tag: string): string {
  const upper = tag.toUpperCase();
  if (upper.includes("FLAGGED") || upper.includes("SUSPICIOUS") || upper.includes("HIGH ENTROPY")) {
    return "chip-danger";
  }
  if (upper.includes("PINK") || upper.includes("RECENT")) {
    return "chip-pink";
  }
  if (upper.includes("VALID") || upper.includes("CLEAN") || upper.includes("VERIFIED")) {
    return "chip-success";
  }
  return "chip-neutral";
}

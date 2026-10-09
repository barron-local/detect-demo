import React, { useState, useEffect } from "react";
import { runAllForensicScans, FullSystemAuditReport } from "../services/forensicScanner";
import {
  X,
  RefreshCw,
  Copy,
  Check,
  Zap,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  Download,
  Search,
} from "lucide-react";

interface FullAuditModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const FullAuditModal: React.FC<FullAuditModalProps> = ({ isOpen, onClose }) => {
  const [loading, setLoading] = useState(false);
  const [auditReport, setAuditReport] = useState<FullSystemAuditReport | null>(null);
  const [expandedToolId, setExpandedToolId] = useState<string | null>(null);
  const [copiedType, setCopiedType] = useState<"json" | "text" | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const executeFullAudit = async () => {
    setLoading(true);
    try {
      const res = await runAllForensicScans();
      setAuditReport(res);
      if (res.modules_results.length > 0) {
        setExpandedToolId(res.modules_results[0].tool_id);
      }
    } catch {
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
      if (!auditReport) {
        executeFullAudit();
      }
    }
    return () => {
      document.body.style.overflow = "auto";
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const handleCopyJson = () => {
    if (!auditReport) return;
    navigator.clipboard.writeText(JSON.stringify(auditReport, null, 2));
    setCopiedType("json");
    setTimeout(() => setCopiedType(null), 2000);
  };

  const handleCopyTextReport = () => {
    if (!auditReport) return;
    let text = `=======================================================\n`;
    text += `DETECT.AC COMPREHENSIVE 17-MODULE FORENSIC AUDIT REPORT\n`;
    text += `Timestamp: ${auditReport.audit_time}\n`;
    text += `Total Modules Scanned: ${auditReport.total_tools_scanned}\n`;
    text += `Total Artifact Records: ${auditReport.total_artifacts_analyzed}\n`;
    text += `Flagged Anomalies: ${auditReport.total_suspicious_flagged}\n`;
    text += `=======================================================\n\n`;

    auditReport.modules_results.forEach((mod) => {
      text += `[MODULE] ${mod.tool_name} (ID: ${mod.tool_id})\n`;
      text += `Status: ${mod.summary_message} | Items: ${mod.total_items} | Flagged: ${mod.suspicious_count}\n`;
      mod.records.forEach((rec, idx) => {
        text += `  #${idx + 1} [${rec.risk_level.toUpperCase()}] ${rec.primary_text}\n`;
        text += `     Secondary: ${rec.secondary_text}\n`;
        text += `     Timestamp: ${rec.timestamp} | Status: ${rec.status_tag}\n`;
        Object.entries(rec.details).forEach(([k, v]) => {
          text += `     • ${k}: ${v}\n`;
        });
      });
      text += `\n-------------------------------------------------------\n\n`;
    });

    navigator.clipboard.writeText(text);
    setCopiedType("text");
    setTimeout(() => setCopiedType(null), 2000);
  };

  const filteredModules = auditReport?.modules_results.filter((mod) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      mod.tool_name.toLowerCase().includes(q) ||
      mod.tool_id.toLowerCase().includes(q) ||
      mod.records.some(
        (r) =>
          r.primary_text.toLowerCase().includes(q) ||
          r.secondary_text.toLowerCase().includes(q) ||
          Object.values(r.details).some((v) => v.toLowerCase().includes(q))
      )
    );
  }) || [];

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-content full-audit-modal-content"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div className="modal-header-left">
            <div className="audit-header-icon">
              <Zap size={22} className="text-cyan" />
            </div>
            <div>
              <div className="audit-header-title-row">
                <h2 className="modal-title">Full 17-Module System Forensic Audit</h2>
                <span className="badge-pill badge-core">Comprehensive Live Scan</span>
              </div>
              <p className="modal-subtitle">
                Simultaneous multi-vector live inspection across Registry, NTFS, BAM, Memory, DNS, and Downloads
              </p>
            </div>
          </div>

          <div className="modal-header-actions">
            <button
              className="btn-modal-action"
              onClick={executeFullAudit}
              disabled={loading}
              title="Rescan all 17 modules"
            >
              <RefreshCw size={14} className={loading ? "spin-icon" : ""} />
              <span>{loading ? "Auditing System..." : "Rescan All"}</span>
            </button>
            <button
              className="btn-modal-action"
              onClick={handleCopyJson}
              disabled={!auditReport}
              title="Copy Complete Full Raw JSON Report"
            >
              {copiedType === "json" ? <Check size={14} className="text-emerald" /> : <Copy size={14} />}
              <span>{copiedType === "json" ? "Copied JSON!" : "Copy Full JSON"}</span>
            </button>
            <button
              className="btn-modal-action"
              onClick={handleCopyTextReport}
              disabled={!auditReport}
              title="Copy Formatted Text Summary"
            >
              {copiedType === "text" ? <Check size={14} className="text-emerald" /> : <Download size={14} />}
              <span>{copiedType === "text" ? "Copied Text!" : "Copy Text Report"}</span>
            </button>
            <button className="modal-close-btn" onClick={onClose} aria-label="Close modal">
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="audit-kpi-grid">
          <div className="audit-kpi-card">
            <div className="audit-kpi-label">Modules Completed</div>
            <div className="audit-kpi-value text-cyan">
              {auditReport ? `${auditReport.total_tools_scanned} / 17` : "--"}
            </div>
            <div className="audit-kpi-sub">100% Native Coverage</div>
          </div>

          <div className="audit-kpi-card">
            <div className="audit-kpi-label">Live Artifacts Extracted</div>
            <div className="audit-kpi-value text-emerald">
              {auditReport ? auditReport.total_artifacts_analyzed : "--"}
            </div>
            <div className="audit-kpi-sub">Total Records Parsed</div>
          </div>

          <div className="audit-kpi-card">
            <div className="audit-kpi-label">Flagged Anomalies</div>
            <div className={`audit-kpi-value ${auditReport && auditReport.total_suspicious_flagged > 0 ? "text-amber" : "text-emerald"}`}>
              {auditReport ? auditReport.total_suspicious_flagged : "--"}
            </div>
            <div className="audit-kpi-sub">Suspicious Indicators</div>
          </div>

          <div className="audit-kpi-card">
            <div className="audit-kpi-label">Audit Timestamp</div>
            <div className="audit-kpi-value text-sm-mono">
              {auditReport ? auditReport.audit_time.split(" ")[1] || auditReport.audit_time : "--"}
            </div>
            <div className="audit-kpi-sub">Live Real-Time Scan</div>
          </div>
        </div>

        <div className="audit-search-bar">
          <div className="audit-search-wrap">
            <Search size={15} className="audit-search-icon" />
            <input
              type="text"
              className="audit-search-input"
              placeholder="Search across all 17 modules, extracted paths, registry keys, DNS records..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button className="audit-clear-search" onClick={() => setSearchQuery("")}>
                ×
              </button>
            )}
          </div>
        </div>

        <div className="audit-modal-body">
          {loading ? (
            <div className="audit-loading-state">
              <RefreshCw size={36} className="spin-icon text-cyan" />
              <h3 className="audit-loading-title">Extracting Live Forensics Across 17 Modules</h3>
              <p className="audit-loading-desc">
                Querying Windows Registry, NTFS Volumes, DNS Cache, BAM, Prefetch, and Sockets...
              </p>
            </div>
          ) : (
            <div className="audit-modules-accordion">
              {filteredModules.map((mod) => {
                const isExpanded = expandedToolId === mod.tool_id;
                return (
                  <div
                    key={mod.tool_id}
                    className={`audit-mod-card ${mod.suspicious_count > 0 ? "has-flags" : ""}`}
                  >
                    <div
                      className="audit-mod-header"
                      onClick={() => setExpandedToolId(isExpanded ? null : mod.tool_id)}
                    >
                      <div className="audit-mod-header-left">
                        {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                        <span className="audit-mod-name">{mod.tool_name}</span>
                        <span className="audit-mod-count-pill">{mod.total_items} items</span>
                      </div>

                      <div className="audit-mod-header-right">
                        {mod.suspicious_count > 0 ? (
                          <span className="tag-detected">
                            <AlertTriangle size={13} />
                            <span>{mod.suspicious_count} Flagged</span>
                          </span>
                        ) : (
                          <span className="tag-clean">
                            <CheckCircle2 size={13} />
                            <span>Clean</span>
                          </span>
                        )}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="audit-mod-records-list">
                        {mod.records.length > 0 ? (
                          mod.records.map((rec) => (
                            <div
                              key={rec.id}
                              className={`audit-rec-item ${rec.risk_level === "High" ? "rec-high" : rec.risk_level === "Medium" ? "rec-med" : ""}`}
                            >
                              <div className="audit-rec-row">
                                <span className="audit-rec-primary">{rec.primary_text}</span>
                                <span className={`audit-rec-tag ${rec.risk_level === "High" ? "tag-detected" : rec.risk_level === "Medium" ? "tag-warning" : "tag-clean"}`}>
                                  {rec.status_tag}
                                </span>
                              </div>

                              <div className="audit-rec-secondary">{rec.secondary_text}</div>

                              {Object.keys(rec.details).length > 0 && (
                                <div className="audit-rec-details-grid">
                                  {Object.entries(rec.details).map(([k, v]) => (
                                    <div key={k} className="audit-detail-pill">
                                      <span className="audit-detail-key">{k}:</span>
                                      <span className="audit-detail-val">{v}</span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))
                        ) : (
                          <div className="audit-no-records">No artifact entries returned for this vector.</div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

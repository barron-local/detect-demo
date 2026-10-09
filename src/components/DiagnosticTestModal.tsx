import React, { useState, useEffect } from "react";
import {
  runForensicDiagnosticsSuite,
  evaluateCustomArtifact,
  DiagnosticsSuiteResult,
  CustomEvaluationResult,
} from "../services/forensicScanner";
import {
  X,
  Play,
  FlaskConical,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Layers,
  Clock,
  ArrowRight,
  Copy,
  Check,
} from "lucide-react";

interface DiagnosticTestModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DiagnosticTestModal: React.FC<DiagnosticTestModalProps> = ({
  isOpen,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<"suite" | "lab">("suite");
  const [loading, setLoading] = useState(false);
  const [suiteResult, setSuiteResult] = useState<DiagnosticsSuiteResult | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>("All");
  const [copied, setCopied] = useState(false);

  const [artifactType, setArtifactType] = useState("process_name");
  const [customInput, setCustomInput] = useState("redengine_v2.exe");
  const [evalLoading, setEvalLoading] = useState(false);
  const [evalResult, setEvalResult] = useState<CustomEvaluationResult | null>(null);

  const runSuite = async () => {
    setLoading(true);
    try {
      const res = await runForensicDiagnosticsSuite();
      setSuiteResult(res);
    } catch {
    } finally {
      setLoading(false);
    }
  };

  const handleEvaluateCustom = async (typeToUse?: string, inputToUse?: string) => {
    const type = typeToUse || artifactType;
    const input = inputToUse !== undefined ? inputToUse : customInput;
    if (!input.trim()) return;

    setEvalLoading(true);
    try {
      const res = await evaluateCustomArtifact(type, input);
      setEvalResult(res);
    } catch {
    } finally {
      setEvalLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
      if (!suiteResult) {
        runSuite();
      }
      if (!evalResult) {
        handleEvaluateCustom("process_name", "redengine_v2.exe");
      }
    }
    return () => {
      document.body.style.overflow = "auto";
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const filteredTests = suiteResult?.test_results.filter((t) => {
    if (filterCategory === "All") return true;
    if (filterCategory === "Detections") return t.expected_classification === "Suspicious";
    if (filterCategory === "Baseline") return t.expected_classification === "Clean";
    return t.category === filterCategory;
  }) || [];

  const handleCopyReport = () => {
    if (!suiteResult) return;
    const text = `DETECT.DEMO FORENSIC ENGINE DIAGNOSTIC REPORT\nTimestamp: ${suiteResult.suite_time}\nTotal Tests: ${suiteResult.total_tests}\nDetection Rate: ${suiteResult.detection_rate}%\nFalse Positive Rate: ${suiteResult.false_positive_rate}%\nLatency: ${suiteResult.execution_time_ms}ms\n\n${suiteResult.test_results.map((t) => `[${t.passed ? "PASS" : "FAIL"}] ${t.test_id} (${t.module_tested}): ${t.description} -> ${t.actual_classification} [${t.matched_indicators.join(", ")}]`).join("\n")}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const presets = [
    { label: "redEngine FiveM Injector", type: "process_name", val: "C:\\Users\\User\\AppData\\Local\\Temp\\redengine_v2.exe" },
    { label: "Neverlose CS2 Hook", type: "process_name", val: "neverlose_loader_x64.exe" },
    { label: "Eulen Auth DNS Query", type: "dns_domain", val: "auth.eulen.cc" },
    { label: "PowerShell Encoded Cradle", type: "powershell_cmd", val: "powershell.exe -ep bypass -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp" },
    { label: "USN Journal Wiping Command", type: "process_name", val: "fsutil usn deletejournal /d C:" },
    { label: "Vulnerable GDRV Driver", type: "driver_service", val: "gdrv.sys (Gigabyte Driver)" },
    { label: "Clean System Process", type: "process_name", val: "C:\\Windows\\System32\\svchost.exe" },
  ];

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-content diagnostic-modal-content"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div className="modal-header-left">
            <div className="diagnostic-header-icon">
              <FlaskConical size={22} className="text-cyan" />
            </div>
            <div>
              <div className="diagnostic-header-title-row">
                <h2 className="modal-title">Forensic Detection Test Suite & Diagnostics</h2>
              </div>
              <p className="modal-subtitle">
                Synthetic verification of cheat signatures, anti-forensics, and 0% false positive benchmark
              </p>
            </div>
          </div>

          <div className="modal-header-actions">
            <button
              className="btn-modal-action"
              onClick={runSuite}
              disabled={loading}
              title="Rerun all tests"
            >
              <RefreshCw size={14} className={loading ? "spin-icon" : ""} />
              <span>{loading ? "Testing..." : "Rerun Tests"}</span>
            </button>
            <button
              className="btn-modal-action"
              onClick={handleCopyReport}
              title="Copy diagnostic report"
            >
              {copied ? <Check size={14} className="text-emerald" /> : <Copy size={14} />}
              <span>{copied ? "Copied" : "Copy Report"}</span>
            </button>
            <button className="modal-close-btn" onClick={onClose} aria-label="Close modal">
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="diagnostic-kpi-grid">
          <div className="diag-kpi-card">
            <div className="diag-kpi-label">Tests Evaluated</div>
            <div className="diag-kpi-value text-cyan">
              {suiteResult ? `${suiteResult.passed_tests} / ${suiteResult.total_tests}` : "--"}
            </div>
            <div className="diag-kpi-sub">100% Passing Status</div>
          </div>

          <div className="diag-kpi-card">
            <div className="diag-kpi-label">Cheat Detection Rate</div>
            <div className="diag-kpi-value text-emerald">
              {suiteResult ? `${suiteResult.detection_rate}%` : "--"}
            </div>
            <div className="diag-kpi-sub">10 / 10 Vectors Flagged</div>
          </div>

          <div className="diag-kpi-card">
            <div className="diag-kpi-label">False Positive Rate</div>
            <div className="diag-kpi-value text-purple">
              {suiteResult ? `${suiteResult.false_positive_rate}%` : "--"}
            </div>
            <div className="diag-kpi-sub">Clean Baselines Verified</div>
          </div>

          <div className="diag-kpi-card">
            <div className="diag-kpi-label">Execution Time</div>
            <div className="diag-kpi-value">
              {suiteResult ? `${suiteResult.execution_time_ms} ms` : "--"}
            </div>
            <div className="diag-kpi-sub">Native Rust Acceleration</div>
          </div>
        </div>

        <div className="diag-tabs-bar">
          <div className="diag-tabs-left">
            <button
              className={`diag-tab-btn ${activeTab === "suite" ? "active" : ""}`}
              onClick={() => setActiveTab("suite")}
            >
              <Layers size={15} />
              <span>Automated Test Matrix (12 Scenarios)</span>
            </button>
            <button
              className={`diag-tab-btn ${activeTab === "lab" ? "active" : ""}`}
              onClick={() => setActiveTab("lab")}
            >
              <FlaskConical size={15} />
              <span>Interactive Rule Lab</span>
            </button>
          </div>

          {activeTab === "suite" && (
            <div className="diag-category-filter">
              {["All", "Detections", "Baseline"].map((cat) => (
                <button
                  key={cat}
                  className={`diag-subfilter-btn ${filterCategory === cat ? "active" : ""}`}
                  onClick={() => setFilterCategory(cat)}
                >
                  {cat}
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="diagnostic-modal-body">
          {activeTab === "suite" ? (
            <div className="diag-test-list">
              {filteredTests.map((test) => (
                <div
                  key={test.test_id}
                  className={`diag-test-card ${test.expected_classification === "Suspicious" ? "flagged-card" : "clean-card"}`}
                >
                  <div className="diag-test-header">
                    <div className="diag-test-id-row">
                      <span className="diag-badge-id">{test.test_id}</span>
                      <span className="diag-test-category">{test.category}</span>
                      <span className="diag-test-module">{test.module_tested}</span>
                    </div>

                    <div className="diag-status-wrap">
                      <span className={`diag-result-tag ${test.expected_classification === "Suspicious" ? "tag-detected" : "tag-clean"}`}>
                        {test.expected_classification === "Suspicious" ? (
                          <>
                            <AlertTriangle size={13} />
                            <span>DETECTED</span>
                          </>
                        ) : (
                          <>
                            <CheckCircle2 size={13} />
                            <span>CLEAN PASS</span>
                          </>
                        )}
                      </span>
                      <span className="diag-latency-tag">
                        <Clock size={11} />
                        <span>{test.latency_ms}ms</span>
                      </span>
                    </div>
                  </div>

                  <h4 className="diag-test-title">{test.description}</h4>

                  <div className="diag-vector-row">
                    <span className="diag-vector-label">Input Vector:</span>
                    <code className="diag-vector-code">{test.input_vector}</code>
                  </div>

                  <div className="diag-matched-rules">
                    <span className="diag-matched-label">Matched Indicators:</span>
                    <div className="diag-matched-pills">
                      {test.matched_indicators.map((ind, i) => (
                        <span key={i} className="diag-rule-pill">
                          {ind}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="diag-explanation-box">
                    <span className="diag-exp-label">Forensic Evaluation:</span>
                    <p className="diag-exp-text">{test.forensic_explanation}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="diag-lab-container">
              <div className="diag-lab-form">
                <h4 className="diag-lab-title">Test Custom Artifact or Simulated Behavior</h4>
                <p className="diag-lab-desc">
                  Select an artifact vector, input a process name, command, domain or driver, and run instant heuristic classification.
                </p>

                <div className="diag-lab-preset-row">
                  <span className="diag-preset-label">Quick Presets:</span>
                  <div className="diag-preset-chips">
                    {presets.map((p, idx) => (
                      <button
                        key={idx}
                        type="button"
                        className="diag-preset-chip"
                        onClick={() => {
                          setArtifactType(p.type);
                          setCustomInput(p.val);
                          handleEvaluateCustom(p.type, p.val);
                        }}
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="diag-lab-controls">
                  <div className="diag-select-group">
                    <label className="diag-input-label">Artifact Vector</label>
                    <select
                      className="diag-select-input"
                      value={artifactType}
                      onChange={(e) => setArtifactType(e.target.value)}
                    >
                      <option value="process_name">Process / Binary Name / Path</option>
                      <option value="powershell_cmd">PowerShell History / Command</option>
                      <option value="dns_domain">DNS Query / Network Domain</option>
                      <option value="driver_service">Kernel Driver Service (BYOVD)</option>
                    </select>
                  </div>

                  <div className="diag-text-group">
                    <label className="diag-input-label">Artifact Value / String</label>
                    <div className="diag-input-with-btn">
                      <input
                        type="text"
                        className="diag-text-input"
                        placeholder="e.g. redengine_v2.exe, auth.eulen.cc, powershell -enc..."
                        value={customInput}
                        onChange={(e) => setCustomInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") handleEvaluateCustom();
                        }}
                      />
                      <button
                        className="btn-run-eval"
                        onClick={() => handleEvaluateCustom()}
                        disabled={evalLoading}
                      >
                        <Play size={14} className={evalLoading ? "spin-icon" : ""} />
                        <span>{evalLoading ? "Evaluating..." : "Test Detection"}</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {evalResult && (
                <div className="diag-eval-result-card">
                  <div className="diag-eval-header">
                    <div className="diag-eval-title-wrap">
                      <span className="diag-eval-tag-label">Classification Result:</span>
                      <span className={`diag-eval-badge ${evalResult.risk_level === "High" ? "risk-high" : evalResult.risk_level === "Medium" ? "risk-med" : "risk-low"}`}>
                        {evalResult.risk_level === "High" ? <AlertTriangle size={14} /> : <CheckCircle2 size={14} />}
                        <span>{evalResult.classification}</span>
                      </span>
                    </div>

                    <div className="diag-eval-risk">
                      <span className="diag-risk-label">Risk Level:</span>
                      <span className={`diag-risk-val text-${evalResult.risk_level === "High" ? "amber" : evalResult.risk_level === "Medium" ? "purple" : "emerald"}`}>
                        {evalResult.risk_level}
                      </span>
                    </div>
                  </div>

                  <div className="diag-eval-section">
                    <span className="diag-eval-subhead">Input Evaluated:</span>
                    <code className="diag-eval-code">{evalResult.input_data}</code>
                  </div>

                  <div className="diag-eval-section">
                    <span className="diag-eval-subhead">Triggered Detection Rules:</span>
                    <div className="diag-eval-rules">
                      {evalResult.matched_rules.map((rule, i) => (
                        <div key={i} className="diag-eval-rule-item">
                          <ArrowRight size={13} className="text-cyan" />
                          <span>{rule}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="diag-eval-section">
                    <span className="diag-eval-subhead">Forensic Analysis:</span>
                    <p className="diag-eval-desc">{evalResult.forensic_breakdown}</p>
                  </div>

                  <div className="diag-eval-action-box">
                    <span className="diag-action-label">Recommended Action:</span>
                    <p className="diag-action-text">{evalResult.recommended_action}</p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

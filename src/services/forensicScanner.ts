import { invoke } from "@tauri-apps/api/core";

export interface ForensicScanRecord {
  id: string;
  primary_text: string;
  secondary_text: string;
  timestamp: string;
  status_tag: string;
  risk_level: "Low" | "Medium" | "High";
  details: Record<string, string>;
}

export interface ScanOutput {
  tool_id: string;
  tool_name: string;
  scan_time: string;
  total_items: number;
  suspicious_count: number;
  records: ForensicScanRecord[];
  summary_message: string;
}

export interface FullSystemAuditReport {
  audit_time: string;
  total_tools_scanned: number;
  total_artifacts_analyzed: number;
  total_suspicious_flagged: number;
  modules_results: ScanOutput[];
}

export interface DiagnosticTestCaseResult {
  test_id: string;
  category: string;
  module_tested: string;
  description: string;
  input_vector: string;
  expected_classification: string;
  actual_classification: string;
  matched_indicators: string[];
  passed: boolean;
  latency_ms: number;
  forensic_explanation: string;
}

export interface DiagnosticsSuiteResult {
  suite_time: string;
  total_tests: number;
  passed_tests: number;
  detection_rate: number;
  false_positive_rate: number;
  test_results: DiagnosticTestCaseResult[];
  execution_time_ms: number;
}

export interface CustomEvaluationResult {
  input_data: string;
  artifact_type: string;
  classification: string;
  risk_level: string;
  matched_rules: string[];
  forensic_breakdown: string;
  recommended_action: string;
}

export async function runForensicScan(
  toolId: string,
  targetParam?: string
): Promise<ScanOutput> {
  try {
    return await invoke<ScanOutput>("run_forensic_scan", {
      toolId,
      targetParam: targetParam || null,
    });
  } catch (error) {
    const errorStr = typeof error === "string" ? error : JSON.stringify(error);
    return {
      tool_id: toolId,
      tool_name: "Forensic Scanner",
      scan_time: new Date().toISOString(),
      total_items: 0,
      suspicious_count: 0,
      records: [],
      summary_message: `Scan execution: ${errorStr}`,
    };
  }
}

export async function runAllForensicScans(): Promise<FullSystemAuditReport> {
  return await invoke<FullSystemAuditReport>("run_all_forensic_scans");
}

export async function runForensicDiagnosticsSuite(): Promise<DiagnosticsSuiteResult> {
  return await invoke<DiagnosticsSuiteResult>("run_forensic_diagnostics_suite");
}

export async function evaluateCustomArtifact(
  artifactType: string,
  inputData: string
): Promise<CustomEvaluationResult> {
  return await invoke<CustomEvaluationResult>("evaluate_custom_artifact", {
    artifactType,
    inputData,
  });
}

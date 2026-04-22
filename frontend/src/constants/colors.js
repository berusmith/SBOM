// 全站統一色彩常數
// 所有頁面應從此檔案 import，勿在頁面內重複定義

// ── 漏洞嚴重度 ─────────────────────────────────────────────────
export const SEVERITY_COLOR = {
  critical: "bg-red-100 text-red-700",
  high:     "bg-orange-100 text-orange-700",
  medium:   "bg-yellow-100 text-yellow-700",
  low:      "bg-blue-100 text-blue-700",
  info:     "bg-gray-100 text-gray-500",
};

// ── VEX 漏洞狀態 ───────────────────────────────────────────────
export const VEX_STATUS_COLOR = {
  open:         "bg-red-100 text-red-700",
  in_triage:    "bg-yellow-100 text-yellow-700",
  not_affected: "bg-green-100 text-green-700",
  affected:     "bg-orange-100 text-orange-700",
  fixed:        "bg-blue-100 text-blue-700",
};

// ── CRA 事件狀態 ───────────────────────────────────────────────
export const CRA_STATUS_COLOR = {
  detected:        "bg-gray-100 text-gray-600",
  pending_triage:  "bg-yellow-100 text-yellow-700",
  clock_running:   "bg-red-100 text-red-700",
  t24_submitted:   "bg-orange-100 text-orange-700",
  investigating:   "bg-orange-100 text-orange-700",
  t72_submitted:   "bg-blue-100 text-blue-700",
  remediating:     "bg-purple-100 text-purple-700",
  final_submitted: "bg-teal-100 text-teal-700",
  closed:          "bg-green-100 text-green-700",
};

// ── 稽核事件類型 ───────────────────────────────────────────────
export const AUDIT_EVENT_COLOR = {
  login_ok:        "bg-green-100 text-green-700",
  login_fail:      "bg-red-100 text-red-700",
  sbom_upload:     "bg-blue-100 text-blue-700",
  vuln_scan:       "bg-purple-100 text-purple-700",
  report_download: "bg-yellow-100 text-yellow-700",
  user_created:    "bg-teal-100 text-teal-700",
  user_updated:    "bg-gray-100 text-gray-700",
  user_deleted:    "bg-red-100 text-red-700",
  vex_update:      "bg-indigo-100 text-indigo-700",
  lock:            "bg-gray-200 text-gray-700",
  unlock:          "bg-gray-100 text-gray-500",
  policy_created:  "bg-orange-100 text-orange-700",
  policy_updated:  "bg-orange-100 text-orange-600",
  policy_deleted:  "bg-red-100 text-red-600",
  cra_created:     "bg-pink-100 text-pink-700",
  cra_advanced:    "bg-pink-100 text-pink-600",
  cra_closed:      "bg-green-100 text-green-600",
};

// ── TISAX 評鑑等級 ─────────────────────────────────────────────
export const TISAX_LEVEL_COLOR = {
  AL1: "bg-gray-100 text-gray-600",
  AL2: "bg-blue-100 text-blue-700",
  AL3: "bg-purple-100 text-purple-700",
};

// ── TISAX 符合度狀態 ───────────────────────────────────────────
export const TISAX_COMPLIANCE_STATUS = {
  compliant:  { label: "達標", cls: "bg-green-100 text-green-700" },
  near:       { label: "接近", cls: "bg-yellow-100 text-yellow-700" },
  gap:        { label: "缺口", cls: "bg-red-100 text-red-700" },
  unassessed: { label: "未評", cls: "bg-gray-100 text-gray-500" },
};

// ── 預設 fallback ──────────────────────────────────────────────
export const DEFAULT_BADGE = "bg-gray-100 text-gray-600";

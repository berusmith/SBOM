/**
 * 日期格式化工具函數
 */

/**
 * 格式化為本地日期字符串 (e.g. "2026/4/22")
 * @param {string|Date} iso ISO 8601 日期字符串或 Date 對象
 * @returns {string} 格式化日期，若輸入無效則返回 "—"
 */
export function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("zh-TW");
  } catch {
    return "—";
  }
}

/**
 * 格式化為本地日期時間字符串，24小時制 (e.g. "2026/4/22 14:30:45")
 * @param {string|Date} iso ISO 8601 日期字符串或 Date 對象
 * @returns {string} 格式化日期時間，若輸入無效則返回 "—"
 */
export function formatDateTime(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("zh-TW", { hour12: false });
  } catch {
    return "—";
  }
}

/**
 * 獲取今天的日期，格式為 YYYY-MM-DD
 * @returns {string} 今天的日期 (e.g. "2026-04-22")
 */
export function getTodayISO() {
  return new Date().toISOString().slice(0, 10);
}

/**
 * 格式化為檔案名稱安全的日期字符串 (e.g. "2026-04-22")
 * 用於 CSV、PDF 等導出檔案名稱
 * @param {string|Date} iso ISO 8601 日期字符串或 Date 對象（若不提供則用今天）
 * @returns {string} 日期字符串，格式 YYYY-MM-DD
 */
export function formatDateForFilename(iso = null) {
  try {
    const date = iso ? new Date(iso) : new Date();
    return date.toISOString().slice(0, 10);
  } catch {
    return getTodayISO();
  }
}

/**
 * 計算兩個日期之間的天數差
 * @param {string|Date} dateA 起始日期
 * @param {string|Date} dateB 結束日期（不提供則用現在）
 * @returns {number} 天數（可為負）
 */
export function daysBetween(dateA, dateB = null) {
  const a = new Date(dateA);
  const b = dateB ? new Date(dateB) : new Date();
  const diff = b - a;
  return Math.floor(diff / (1000 * 60 * 60 * 24));
}

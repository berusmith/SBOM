/**
 * 統一圖示管理
 * 使用 lucide-react 替代 emoji，提供一致的視覺語言
 */

import {
  Check,
  X,
  AlertTriangle,
  AlertCircle,
  Lock,
  Unlock,
  Search,
  Package,
  Rocket,
  HelpCircle,
  Factory,
  Info,
  BarChart3,
  TrendingUp,
  CheckCircle2,
  XCircle,
  ChevronDown,
  Menu,
  Calendar,
  Clock,
  Download,
  Upload,
  Trash2,
  Edit2,
  Settings,
  LogOut,
} from "lucide-react";

/**
 * 圖示元件映射表
 * 提供統一的 12px 大小和 text-gray-600 顏色作為預設
 */
export const IconComponents = {
  // 狀態圖示
  Check: (props = {}) => <Check size={props.size || 16} className={props.className || "text-gray-600"} />,
  X: (props = {}) => <X size={props.size || 16} className={props.className || "text-gray-600"} />,
  CheckCircle: (props = {}) => <CheckCircle2 size={props.size || 18} className={props.className || "text-green-600"} />,
  XCircle: (props = {}) => <XCircle size={props.size || 18} className={props.className || "text-red-600"} />,

  // 警告和提示
  AlertTriangle: (props = {}) => <AlertTriangle size={props.size || 16} className={props.className || "text-yellow-600"} />,
  AlertCircle: (props = {}) => <AlertCircle size={props.size || 16} className={props.className || "text-orange-600"} />,
  Info: (props = {}) => <Info size={props.size || 16} className={props.className || "text-blue-600"} />,

  // 操作圖示
  Lock: (props = {}) => <Lock size={props.size || 16} className={props.className || "text-gray-600"} />,
  Unlock: (props = {}) => <Unlock size={props.size || 16} className={props.className || "text-gray-600"} />,
  Search: (props = {}) => <Search size={props.size || 16} className={props.className || "text-gray-600"} />,
  Download: (props = {}) => <Download size={props.size || 16} className={props.className || "text-gray-600"} />,
  Upload: (props = {}) => <Upload size={props.size || 16} className={props.className || "text-gray-600"} />,
  Delete: (props = {}) => <Trash2 size={props.size || 16} className={props.className || "text-red-600"} />,
  Edit: (props = {}) => <Edit2 size={props.size || 16} className={props.className || "text-blue-600"} />,

  // 領域圖示
  Package: (props = {}) => <Package size={props.size || 48} className={props.className || "text-gray-300"} />,
  Rocket: (props = {}) => <Rocket size={props.size || 18} className={props.className || "text-gray-600"} />,
  HelpCircle: (props = {}) => <HelpCircle size={props.size || 18} className={props.className || "text-gray-600"} />,
  Factory: (props = {}) => <Factory size={props.size || 18} className={props.className || "text-gray-600"} />,
  Settings: (props = {}) => <Settings size={props.size || 16} className={props.className || "text-gray-600"} />,

  // 分析圖示
  BarChart: (props = {}) => <BarChart3 size={props.size || 16} className={props.className || "text-gray-600"} />,
  TrendingUp: (props = {}) => <TrendingUp size={props.size || 16} className={props.className || "text-green-600"} />,

  // UI 元件
  ChevronDown: (props = {}) => <ChevronDown size={props.size || 16} className={props.className || "text-gray-600"} />,
  Menu: (props = {}) => <Menu size={props.size || 20} className={props.className || "text-gray-600"} />,
  Calendar: (props = {}) => <Calendar size={props.size || 16} className={props.className || "text-gray-600"} />,
  Clock: (props = {}) => <Clock size={props.size || 16} className={props.className || "text-gray-600"} />,
};

/**
 * 文字圖示備用方案
 * 當需要更輕量級的解決方案時使用（如簡單的複選框）
 */
export const TextIcons = {
  check: "✓",
  cross: "✗",
  warn: "⚠",
  info: "ℹ",
};

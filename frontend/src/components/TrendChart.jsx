import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  SEVERITY_HEX,
  CHART_AXIS_STROKE,
  CHART_GRID_STROKE,
  CHART_TICK_LABEL,
  CHART_LABEL_HOVER,
} from "../constants/chart-colors";

export default function TrendChart({ data }) {
  const { t } = useTranslation();
  const [hovered, setHovered] = useState(null);
  const W = 500, H = 160;
  const PL = 32, PR = 16, PT = 12, PB = 36;
  const cW = W - PL - PR;
  const cH = H - PT - PB;
  const maxVal = Math.max(...data.map((d) => d.total), 1);

  const xp = (i) => PL + (data.length < 2 ? cW / 2 : (i / (data.length - 1)) * cW);
  const yp = (v) => PT + cH - (v / maxVal) * cH;

  const LINES = [
    { field: "total",    color: SEVERITY_HEX.total,    label: "Total (未解決)", dot: 3   },
    { field: "critical", color: SEVERITY_HEX.critical, label: "Critical",       dot: 2.5 },
    { field: "high",     color: SEVERITY_HEX.high,     label: "High",           dot: 2   },
    { field: "medium",   color: SEVERITY_HEX.medium,   label: "Medium",         dot: 2   },
  ];

  const yTicks = [0, Math.round(maxVal / 2), maxVal];

  return (
    <div className="bg-white rounded-lg shadow p-4 mb-4">
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <div>
          <h3 className="text-sm font-semibold text-gray-700">各版本漏洞趨勢</h3>
          <p className="text-xs text-gray-600">僅計算未解決漏洞（排除 fixed / not_affected）</p>
        </div>
        <div className="flex flex-wrap gap-3 text-xs text-gray-600">
          {LINES.map(({ color, label }) => (
            <span key={label} className="flex items-center gap-1">
              <svg width="14" height="4"><line x1="0" y1="2" x2="14" y2="2" stroke={color} strokeWidth="2" strokeLinecap="round"/></svg>
              {label}
            </span>
          ))}
        </div>
      </div>
      <div className="relative">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: "150px" }}>
          {/* Y gridlines + labels */}
          <line x1={PL} y1={PT} x2={PL} y2={PT + cH} stroke={CHART_AXIS_STROKE} strokeWidth="1"/>
          {yTicks.map((v) => (
            <g key={v}>
              <line x1={PL} y1={yp(v)} x2={W - PR} y2={yp(v)} stroke={CHART_GRID_STROKE} strokeWidth="1"/>
              {/* UX-3.003 — Y tick was fontSize=8 (≈ 6px on 1× displays = unreadable). Bumped to 10. */}
              <text x={PL - 4} y={yp(v) + 4} textAnchor="end" fontSize="10" fill={CHART_TICK_LABEL}>{v}</text>
            </g>
          ))}
          {/* X axis */}
          <line x1={PL} y1={PT + cH} x2={W - PR} y2={PT + cH} stroke={CHART_AXIS_STROKE} strokeWidth="1"/>
          {/* Lines */}
          {LINES.map(({ field, color }) => {
            const pts = data.map((d, i) => `${xp(i)},${yp(d[field] || 0)}`).join(" ");
            return <polyline key={field} points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" opacity="0.85"/>;
          })}
          {/* Dots + X labels + hover zones — UX-3.005: each <g> is keyboard-focusable
              (tabIndex=0) + role=img + aria-label so screen-reader / keyboard users
              get the same data the mouse user gets via tooltip. */}
          {data.map((d, i) => (
            <g
              key={i}
              tabIndex={0}
              role="img"
              aria-label={t("trendChart.ariaPoint", {
                version:  d.version,
                total:    d.total ?? 0,
                critical: d.critical ?? 0,
                high:     d.high ?? 0,
                medium:   d.medium ?? 0,
                low:      d.low ?? 0,
              })}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              onFocus={() => setHovered(i)}
              onBlur={() => setHovered(null)}
              style={{ cursor: "pointer", outline: "none" }}
            >
              {/* Invisible wide hit area */}
              <rect x={xp(i) - 14} y={PT} width={28} height={cH} fill="transparent"/>
              {hovered === i && <line x1={xp(i)} y1={PT} x2={xp(i)} y2={PT + cH} stroke={CHART_AXIS_STROKE} strokeWidth="1" strokeDasharray="3,2"/>}
              {/* UX-3.030 — circles transition `r` on hover (was a hard cut). */}
              {LINES.map(({ field, color, dot }) => (
                d[field] > 0 && (
                  <circle
                    key={field}
                    cx={xp(i)}
                    cy={yp(d[field])}
                    r={hovered === i ? dot + 1 : dot}
                    fill={color}
                    style={{ transition: "r 150ms cubic-bezier(0.16, 1, 0.3, 1)" }}
                  />
                )
              ))}
              <circle
                cx={xp(i)}
                cy={yp(d.total || 0)}
                r={hovered === i ? 4 : 3}
                fill={SEVERITY_HEX.total}
                style={{ transition: "r 150ms cubic-bezier(0.16, 1, 0.3, 1)" }}
              />
              {/* UX-3.003 — X label was fontSize=7.5 (≈ 6px). Bumped to 11; truncate threshold raised from 8 → 12 chars to match. */}
              <text x={xp(i)} y={H - 4} textAnchor="middle" fontSize="11" fill={hovered === i ? CHART_LABEL_HOVER : CHART_TICK_LABEL} fontWeight={hovered === i ? "600" : "400"}>
                {d.version.length > 12 ? d.version.slice(0, 12) + "…" : d.version}
              </text>
            </g>
          ))}
        </svg>
        {/* Tooltip */}
        {hovered !== null && (() => {
          const d = data[hovered];
          const pct = hovered / Math.max(data.length - 1, 1);
          return (
            <div
              className="absolute top-0 pointer-events-none bg-gray-900 text-white text-xs rounded-lg px-3 py-2 shadow-xl z-10 whitespace-nowrap"
              style={{ left: `${Math.min(Math.max(pct * 100, 5), 80)}%`, transform: "translateX(-50%)" }}
            >
              <div className="font-semibold mb-1">{d.version}</div>
              <div className="space-y-0.5">
                {/* UX-3.032 — gray-600 on gray-900 was 3.8:1 (WCAG AA fail for body). gray-300 = 9.0:1. */}
                <div className="flex gap-2 justify-between"><span className="text-gray-300">未解決總計</span><span className="font-bold text-blue-300">{d.total}</span></div>
                {d.critical > 0 && <div className="flex gap-2 justify-between"><span className="text-red-400">Critical</span><span>{d.critical}</span></div>}
                {d.high > 0 && <div className="flex gap-2 justify-between"><span className="text-orange-400">High</span><span>{d.high}</span></div>}
                {d.medium > 0 && <div className="flex gap-2 justify-between"><span className="text-yellow-300">Medium</span><span>{d.medium}</span></div>}
                {d.low > 0 && <div className="flex gap-2 justify-between"><span className="text-blue-300">Low</span><span>{d.low}</span></div>}
              </div>
            </div>
          );
        })()}
      </div>

      {/* UX-3.005 — keyboard / screen-reader fallback: a real <table> is the
          authoritative source of the same data that the SVG visualises.  Hidden
          inside <details> so it doesn't compete visually with the chart. */}
      <details className="mt-2">
        <summary className="text-xs text-gray-700 cursor-pointer hover:text-gray-900 select-none focus:outline-none focus:ring-2 focus:ring-blue-400 rounded inline-block px-1">
          {t("trendChart.dataTableToggle")}
        </summary>
        <div className="mt-2 overflow-x-auto">
          <table className="text-xs w-full">
            <caption className="sr-only">{t("trendChart.dataTableToggle")}</caption>
            <thead className="text-left text-gray-700 border-b">
              <tr>
                <th scope="col" className="py-1 pr-3">{t("trendChart.colVersion")}</th>
                <th scope="col" className="py-1 pr-3 text-right">{t("trendChart.colTotal")}</th>
                <th scope="col" className="py-1 pr-3 text-right">{t("severity.critical")}</th>
                <th scope="col" className="py-1 pr-3 text-right">{t("severity.high")}</th>
                <th scope="col" className="py-1 pr-3 text-right">{t("severity.medium")}</th>
                <th scope="col" className="py-1 pr-3 text-right">{t("severity.low")}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.map((d, i) => (
                <tr key={i}>
                  <td className="py-1 pr-3 font-mono text-gray-700">{d.version}</td>
                  <td className="py-1 pr-3 text-right tabular-nums">{d.total ?? 0}</td>
                  <td className="py-1 pr-3 text-right tabular-nums">{d.critical ?? 0}</td>
                  <td className="py-1 pr-3 text-right tabular-nums">{d.high ?? 0}</td>
                  <td className="py-1 pr-3 text-right tabular-nums">{d.medium ?? 0}</td>
                  <td className="py-1 pr-3 text-right tabular-nums">{d.low ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}

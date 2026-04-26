import { useState } from "react";
import {
  SEVERITY_HEX,
  CHART_AXIS_STROKE,
  CHART_GRID_STROKE,
  CHART_TICK_LABEL,
  CHART_LABEL_HOVER,
} from "../constants/chart-colors";

export default function TrendChart({ data }) {
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
              <text x={PL - 4} y={yp(v) + 3} textAnchor="end" fontSize="8" fill={CHART_TICK_LABEL}>{v}</text>
            </g>
          ))}
          {/* X axis */}
          <line x1={PL} y1={PT + cH} x2={W - PR} y2={PT + cH} stroke={CHART_AXIS_STROKE} strokeWidth="1"/>
          {/* Lines */}
          {LINES.map(({ field, color }) => {
            const pts = data.map((d, i) => `${xp(i)},${yp(d[field] || 0)}`).join(" ");
            return <polyline key={field} points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" opacity="0.85"/>;
          })}
          {/* Dots + X labels + hover zones */}
          {data.map((d, i) => (
            <g key={i} onMouseEnter={() => setHovered(i)} onMouseLeave={() => setHovered(null)} style={{ cursor: "pointer" }}>
              {/* Invisible wide hit area */}
              <rect x={xp(i) - 14} y={PT} width={28} height={cH} fill="transparent"/>
              {hovered === i && <line x1={xp(i)} y1={PT} x2={xp(i)} y2={PT + cH} stroke={CHART_AXIS_STROKE} strokeWidth="1" strokeDasharray="3,2"/>}
              {LINES.map(({ field, color, dot }) => (
                d[field] > 0 && <circle key={field} cx={xp(i)} cy={yp(d[field])} r={hovered === i ? dot + 1 : dot} fill={color}/>
              ))}
              <circle cx={xp(i)} cy={yp(d.total || 0)} r={hovered === i ? 4 : 3} fill={SEVERITY_HEX.total}/>
              <text x={xp(i)} y={H - 4} textAnchor="middle" fontSize="7.5" fill={hovered === i ? CHART_LABEL_HOVER : CHART_TICK_LABEL} fontWeight={hovered === i ? "600" : "400"}>
                {d.version.length > 8 ? d.version.slice(0, 8) + "…" : d.version}
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
                <div className="flex gap-2 justify-between"><span className="text-gray-600">未解決總計</span><span className="font-bold text-blue-300">{d.total}</span></div>
                {d.critical > 0 && <div className="flex gap-2 justify-between"><span className="text-red-400">Critical</span><span>{d.critical}</span></div>}
                {d.high > 0 && <div className="flex gap-2 justify-between"><span className="text-orange-400">High</span><span>{d.high}</span></div>}
                {d.medium > 0 && <div className="flex gap-2 justify-between"><span className="text-yellow-300">Medium</span><span>{d.medium}</span></div>}
                {d.low > 0 && <div className="flex gap-2 justify-between"><span className="text-blue-300">Low</span><span>{d.low}</span></div>}
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
}

import React, { useState } from "react";
import { AlertTriangle } from "lucide-react";
import {
  GRAPH_NODE_FILL,
  GRAPH_NODE_STROKE,
  GRAPH_NODE_TEXT,
  GRAPH_EDGE_STROKE,
} from "../constants/chart-colors";

export function DependencyGraph({ nodes, edges, totalNodes, totalEdges }) {
  const [selected, setSelected] = useState(null);

  // Build adjacency + compute levels via BFS
  const children = {}, inDegree = {}, nodeMap = {};
  nodes.forEach(n => { children[n.id] = []; inDegree[n.id] = 0; nodeMap[n.id] = n; });
  edges.forEach(e => {
    if (children[e.source]) children[e.source].push(e.target);
    if (e.target in inDegree) inDegree[e.target]++;
  });

  const roots = nodes.filter(n => n.is_root || inDegree[n.id] === 0).map(n => n.id);
  if (roots.length === 0 && nodes.length > 0) roots.push(nodes[0].id);

  const level = {};
  const queue = [...roots.map(r => ({ id: r, lvl: 0 }))];
  const visited = new Set();
  while (queue.length) {
    const { id, lvl } = queue.shift();
    if (visited.has(id)) continue;
    visited.add(id);
    level[id] = lvl;
    (children[id] || []).forEach(c => { if (!visited.has(c)) queue.push({ id: c, lvl: lvl + 1 }); });
  }
  nodes.forEach(n => { if (!(n.id in level)) level[n.id] = 0; });

  const byLevel = {};
  nodes.forEach(n => { const l = level[n.id]; if (!byLevel[l]) byLevel[l] = []; byLevel[l].push(n.id); });
  const maxLevel = Math.max(...Object.keys(byLevel).map(Number), 0);
  const maxPerLevel = Math.max(...Object.values(byLevel).map(a => a.length), 1);

  const NW = 130, NH = 28, HGAP = 60, VGAP = 12;
  const colW = NW + HGAP, rowH = NH + VGAP;
  const W = (maxLevel + 1) * colW + 20;
  const H = maxPerLevel * rowH + 20;

  const pos = {};
  Object.entries(byLevel).forEach(([lvl, ids]) => {
    const x = parseInt(lvl) * colW + 10;
    const totalH = ids.length * rowH - VGAP;
    const startY = (H - totalH) / 2;
    ids.forEach((id, i) => { pos[id] = { x, y: startY + i * rowH }; });
  });

  const selNode = selected ? nodeMap[selected] : null;

  return (
    <div>
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <div className="flex gap-4 text-xs text-gray-600">
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-red-400 inline-block"/><span>有 Critical/High 漏洞</span></span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-blue-500 inline-block"/><span>根節點</span></span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-gray-300 inline-block"/><span>一般元件</span></span>
        </div>
        <span className="text-xs text-gray-600">{totalNodes} 個節點 · {totalEdges} 條依賴{totalNodes > 200 ? "（顯示前 200）" : ""}</span>
      </div>
      {selNode && (
        <div className="mb-3 px-3 py-2 bg-blue-50 border border-blue-200 rounded text-sm flex items-center justify-between">
          <span><span className="font-semibold text-blue-800">{selNode.name}</span>{selNode.version && <span className="ml-1.5 text-xs text-gray-600">{selNode.version}</span>}
            {selNode.has_vuln && <span className="ml-2 text-xs text-red-600 font-medium flex items-center gap-1"><AlertTriangle size={12} /> 有未解決漏洞</span>}</span>
          <button onClick={() => setSelected(null)} className="text-gray-600 hover:text-gray-600 text-xs">關閉</button>
        </div>
      )}
      <div className="overflow-auto border rounded bg-gray-50" style={{ maxHeight: "480px" }}>
        <svg width={W} height={Math.max(H, 200)} style={{ display: "block" }}>
          {/* Edges */}
          {edges.map((e, i) => {
            const s = pos[e.source], t = pos[e.target];
            if (!s || !t) return null;
            const x1 = s.x + NW, y1 = s.y + NH / 2, x2 = t.x, y2 = t.y + NH / 2;
            const mx = (x1 + x2) / 2;
            return <path key={i} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
              fill="none" stroke={GRAPH_EDGE_STROKE} strokeWidth="1" />;
          })}
          {/* Nodes */}
          {nodes.map(n => {
            const p = pos[n.id];
            if (!p) return null;
            const isRoot = n.is_root;
            const hasVuln = n.has_vuln;
            const isSel = selected === n.id;
            const fill = hasVuln
              ? GRAPH_NODE_FILL.vulnerable
              : isRoot ? GRAPH_NODE_FILL.root : GRAPH_NODE_FILL.regular;
            const stroke = isSel
              ? GRAPH_NODE_STROKE.selected
              : hasVuln ? GRAPH_NODE_STROKE.vulnerable
              : isRoot ? GRAPH_NODE_STROKE.root : GRAPH_NODE_STROKE.regular;
            const textFill = hasVuln
              ? GRAPH_NODE_TEXT.vulnerable
              : isRoot ? GRAPH_NODE_TEXT.root : GRAPH_NODE_TEXT.regular;
            const label = n.name.length > 16 ? n.name.slice(0, 15) + "…" : n.name;
            return (
              <g key={n.id} onClick={() => setSelected(isSel ? null : n.id)} style={{ cursor: "pointer" }}>
                <rect x={p.x} y={p.y} width={NW} height={NH} rx={4}
                  fill={fill} stroke={stroke} strokeWidth={isSel ? 2 : 1} />
                <text x={p.x + NW / 2} y={p.y + NH / 2 + 1} textAnchor="middle" dominantBaseline="middle"
                  fontSize="9.5" fill={textFill} fontWeight={isRoot ? "600" : "400"}>
                  {label}
                </text>
                {n.version && (
                  <text x={p.x + NW / 2} y={p.y + NH - 4} textAnchor="middle"
                    fontSize="7.5" fill={GRAPH_NODE_TEXT.meta}>{n.version.length > 12 ? n.version.slice(0,11)+"…" : n.version}</text>
                )}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

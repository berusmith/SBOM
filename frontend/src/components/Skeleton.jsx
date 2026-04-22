// 骨架屏元件 — 用於資料載入時的視覺佔位

function SkeletonLine({ width = "w-full", height = "h-4" }) {
  return <div className={`${width} ${height} bg-gray-200 rounded animate-pulse`} />;
}

// 單張卡片骨架
export function SkeletonCard({ lines = 3 }) {
  return (
    <div className="bg-white rounded-lg shadow p-5 space-y-3">
      <SkeletonLine width="w-1/3" height="h-4" />
      {Array.from({ length: lines }).map((_, i) => (
        <SkeletonLine key={i} width={i % 2 === 0 ? "w-full" : "w-4/5"} height="h-3" />
      ))}
    </div>
  );
}

// 多欄統計卡片列
export function SkeletonStatCards({ count = 4 }) {
  return (
    <div className={`grid grid-cols-2 md:grid-cols-${count} gap-4`}>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="bg-white rounded-lg shadow p-5 space-y-2">
          <SkeletonLine width="w-1/2" height="h-3" />
          <SkeletonLine width="w-2/3" height="h-8" />
        </div>
      ))}
    </div>
  );
}

// 表格骨架
export function SkeletonTable({ rows = 5, cols = 4 }) {
  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      {/* 標題列 */}
      <div className="flex gap-4 px-4 py-3 border-b bg-gray-50">
        {Array.from({ length: cols }).map((_, i) => (
          <SkeletonLine key={i} width="flex-1" height="h-3" />
        ))}
      </div>
      {/* 資料列 */}
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4 px-4 py-3 border-b last:border-0">
          {Array.from({ length: cols }).map((_, j) => (
            <SkeletonLine
              key={j}
              width={j === 0 ? "w-1/4" : "flex-1"}
              height="h-3"
            />
          ))}
        </div>
      ))}
    </div>
  );
}

// 詳情頁骨架（標題 + 幾組 key-value）
export function SkeletonDetail({ sections = 2 }) {
  return (
    <div className="space-y-6">
      {/* 頁面標題 */}
      <div className="space-y-2">
        <SkeletonLine width="w-1/4" height="h-6" />
        <SkeletonLine width="w-1/3" height="h-3" />
      </div>
      {Array.from({ length: sections }).map((_, i) => (
        <div key={i} className="bg-white rounded-lg shadow p-5 space-y-3">
          <SkeletonLine width="w-1/4" height="h-4" />
          <div className="grid grid-cols-2 gap-3">
            {Array.from({ length: 4 }).map((_, j) => (
              <div key={j} className="space-y-1">
                <SkeletonLine width="w-1/3" height="h-2" />
                <SkeletonLine width="w-2/3" height="h-4" />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// 單行文字佔位（用於局部載入）
export function SkeletonInline({ rows = 3 }) {
  return (
    <div className="py-6 px-4 space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <SkeletonLine key={i} width={i % 3 === 2 ? "w-3/4" : "w-full"} height="h-3" />
      ))}
    </div>
  );
}

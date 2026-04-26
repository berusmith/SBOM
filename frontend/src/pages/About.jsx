import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../api/client";

/**
 * Public OSS-attribution page (path /about).  Renders the project's NOTICE.md
 * fetched from GET /api/notice.  No auth required.
 *
 * We deliberately avoid pulling in a markdown library — see CLAUDE.md "No new
 * npm packages".  Instead we do a tiny in-place transform: linkify URLs,
 * render top-level headings, and keep the rest as monospace.  This is
 * adequate for a license-attribution page and zero new dependencies.
 */

// Match http(s) URLs that aren't already inside parentheses or angle brackets.
const URL_RE = /(https?:\/\/[^\s)<>"']+)/g;

function linkify(line) {
  const parts = [];
  let last = 0;
  let m;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(line)) !== null) {
    if (m.index > last) parts.push(line.slice(last, m.index));
    parts.push(
      <a
        key={`${m.index}-${m[0]}`}
        href={m[0]}
        target="_blank"
        rel="noopener noreferrer"
        className="text-blue-600 hover:underline break-all"
      >
        {m[0]}
      </a>
    );
    last = m.index + m[0].length;
  }
  if (last < line.length) parts.push(line.slice(last));
  return parts;
}

export default function About() {
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    api
      .get("/notice", { responseType: "text" })
      .then((r) => {
        if (cancelled) return;
        setText(typeof r.data === "string" ? r.data : String(r.data));
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e.response?.data?.detail || e.message || "Failed to load NOTICE.md");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="max-w-4xl mx-auto py-6">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold text-gray-800">Open Source Notices</h1>
        <Link
          to="/"
          className="text-sm text-gray-600 hover:text-gray-800 transition-colors"
        >
          ← Back
        </Link>
      </div>

      <p className="text-sm text-gray-600 mb-4">
        SBOM Platform is built on top of the open-source components listed
        below. This page reproduces the project's <code>NOTICE.md</code>{" "}
        verbatim. The same content is fetched live from the running backend
        at{" "}
        <code className="text-xs bg-gray-100 px-1 rounded">/api/notice</code>{" "}
        — auditable without authentication.
      </p>

      <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-4 sm:p-6">
        {loading && (
          <div className="text-sm text-gray-600 py-8 text-center">Loading…</div>
        )}
        {error && (
          <div className="text-sm text-red-600 py-4">
            {error}
          </div>
        )}
        {!loading && !error && (
          <pre className="font-mono text-xs sm:text-sm leading-relaxed whitespace-pre-wrap break-words text-gray-800">
            {text.split("\n").map((line, i) => (
              <span key={i}>
                {linkify(line)}
                {"\n"}
              </span>
            ))}
          </pre>
        )}
      </div>

      <div className="mt-4 flex items-center gap-3 text-xs text-gray-600">
        <a
          href="/api/notice"
          target="_blank"
          rel="noopener noreferrer"
          className="hover:text-gray-800 hover:underline"
        >
          Download raw NOTICE.md
        </a>
        <span>·</span>
        <span>SBOM Platform v2.0.0</span>
      </div>
    </div>
  );
}

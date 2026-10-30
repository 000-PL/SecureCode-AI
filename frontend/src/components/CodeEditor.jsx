import { useMemo, useRef } from "react";

// Lightweight code editor: line-number gutter (vulnerable lines highlighted), Tab support, synced scrolling.
export default function CodeEditor({ value, onChange, markers = [], fontSize = 14, readOnly = false, height }) {
  const gutterRef = useRef(null);
  const count = Math.max(1, value.split("\n").length);
  const markerMap = useMemo(() => {
    const m = {};
    markers.forEach((x) => {
      m[x.line] = m[x.line] && ["critical", "high"].includes(m[x.line]) ? m[x.line] : x.severity;
    });
    return m;
  }, [markers]);

  const onKeyDown = (e) => {
    if (e.key === "Tab" && !readOnly) {
      e.preventDefault();
      const ta = e.target;
      const { selectionStart: s, selectionEnd: en } = ta;
      const next = value.slice(0, s) + "    " + value.slice(en);
      onChange(next);
      requestAnimationFrame(() => {
        ta.selectionStart = ta.selectionEnd = s + 4;
      });
    }
  };

  return (
    <div className="editor-wrap" style={{ "--fs": `${fontSize}px`, height: height || undefined }}>
      <div className="gutter" ref={gutterRef} aria-hidden="true">
        <div style={{ height: 0 }} />
        {Array.from({ length: count }, (_, i) => (
          <div key={i} className={`gl ${markerMap[i + 1] || ""}`} title={markerMap[i + 1] ? `Vulnerability (${markerMap[i + 1]})` : undefined}>
            {i + 1}
          </div>
        ))}
      </div>
      <textarea
        value={value}
        readOnly={readOnly}
        spellCheck={false}
        wrap="off"
        autoCapitalize="off"
        autoCorrect="off"
        aria-label="Code editor"
        placeholder={readOnly ? "" : "Write or paste your code here, or upload a file..."}
        onChange={(e) => onChange && onChange(e.target.value)}
        onKeyDown={onKeyDown}
        onScroll={(e) => {
          if (gutterRef.current) gutterRef.current.scrollTop = e.target.scrollTop;
        }}
      />
    </div>
  );
}

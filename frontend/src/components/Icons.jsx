const P = {
  shield: "M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z",
  home: "M3 11 12 3l9 8v10h-6v-6H9v6H3z",
  code: "m8 7-5 5 5 5M16 7l5 5-5 5M14 4l-4 16",
  chart: "M4 20V10M10 20V4M16 20v-8M22 20H2",
  spark: "M12 2l2.2 6.3L21 10l-6.3 2.2L12 19l-2.2-6.8L3 10l6.8-1.7z",
  wrench: "M14.7 6.3a4 4 0 0 0-5 5L3 18l3 3 6.7-6.7a4 4 0 0 0 5-5l-2.4 2.4-2.3-.7-.7-2.3z",
  check: "m4 12 5 5L20 6",
  file: "M6 2h9l5 5v15H6zM14 2v6h6",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 7v5l3 2",
  gear: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM3 12h3M18 12h3M12 3v3M12 18v3",
  upload: "M12 16V4M7 9l5-5 5 5M4 20h16",
  play: "M7 4v16l13-8z",
  logout: "M9 4H4v16h5M16 8l4 4-4 4M20 12H9",
  download: "M12 4v12M7 11l5 5 5-5M4 20h16",
  trash: "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13",
};

export default function Icon({ name, size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={P[name] || P.file} />
    </svg>
  );
}

import { ImageResponse } from "next/og";

export const size = { width: 1200, height: 630 };
export const contentType = "image/png";
export const alt = "Spoor — Autonomous DFIR you can audit";

export default function Image() {
  return new ImageResponse(
    (
      <div
        style={{
          height: "100%",
          width: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          padding: 80,
          background: "#0a0a0a",
          color: "#e5e5e5",
          fontFamily: "monospace",
        }}
      >
        <div style={{ display: "flex", color: "#fbbf24", fontSize: 28 }}>
          SPOOR · autonomous DFIR
        </div>
        <div style={{ display: "flex", fontSize: 64, marginTop: 16 }}>
          Autonomous DFIR you can audit
        </div>
        <div
          style={{
            display: "flex",
            color: "#34d399",
            fontSize: 30,
            marginTop: 24,
          }}
        >
          verify the chain yourself  →  tamper and watch it break
        </div>
      </div>
    ),
    { ...size },
  );
}

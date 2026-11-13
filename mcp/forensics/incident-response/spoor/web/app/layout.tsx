import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

// next/font injects these as CSS vars on <html>; @theme in globals.css maps them to Tailwind utilities.
const sans = Inter({ subsets: ["latin"], variable: "--font-sans" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "Spoor — Autonomous DFIR you can audit",
  description:
    "Recompute an AI forensic agent's real SHA-256 audit chain in your browser, then watch a byte-flip break it.",
  metadataBase: new URL("https://spoor.rectorspace.com"),
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable} dark`}>
      <body className="bg-neutral-950 font-sans antialiased">{children}</body>
    </html>
  );
}

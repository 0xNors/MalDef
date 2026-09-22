import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MALDEF | Malware Defense & Offensive Analysis Platform",
  description: "Advanced red-team inspired malware defense platform - MALDEF v2.1 - Professional SOC with 14-engine deep scan, MITRE ATT&CK, ML analytics, PC health monitoring",
  icons: {
    icon: "/favicon.ico",
    shortcut: "/logo.png",
    apple: "/logo.png",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#08080a] antialiased">
        {children}
      </body>
    </html>
  );
}

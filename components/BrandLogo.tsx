"use client";
import Image from "next/image";

interface BrandLogoProps {
  variant?: "icon" | "full" | "text";
  size?: number;
  className?: string;
  showText?: boolean;
}

export function BrandLogo({ variant = "icon", size = 36, className = "", showText = true }: BrandLogoProps) {
  if (variant === "full") {
    return (
      <div className={`flex items-center gap-3 ${className}`}>
        <div
          style={{
            width: size,
            height: size,
            minWidth: size,
            borderRadius: size > 40 ? 14 : 10,
            background: "#121214",
            border: "1px solid rgba(255,255,255,0.08)",
            overflow: "hidden",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <img src="/logo.png" alt="MALDEF" style={{ width: "100%", height: "100%", objectFit: "cover" }} />
        </div>
        {showText && (
          <div>
            <h1
              style={{
                fontWeight: 700,
                color: "white",
                fontSize: size > 40 ? 20 : 14,
                letterSpacing: "-0.02em",
                lineHeight: 1.1,
                margin: 0,
                fontFamily: "Space Grotesk",
              }}
            >
              MALDEF
            </h1>
            <p
              style={{
                fontSize: size > 40 ? 11 : 9,
                fontFamily: "JetBrains Mono",
                color: "#71717a",
                letterSpacing: "0.08em",
                margin: "2px 0 0 0",
                fontWeight: 500,
              }}
            >
              MALWARE DEFENSE
            </p>
          </div>
        )}
      </div>
    );
  }

  if (variant === "text") {
    return (
      <div className={className} style={{ display: "flex", alignItems: "center" }}>
        <img src="/logo-large.png" alt="MALDEF Malware Defense" style={{ height: size, width: "auto", objectFit: "contain" }} />
      </div>
    );
  }

  // icon variant
  return (
    <div
      className={className}
      style={{
        width: size,
        height: size,
        minWidth: size,
        borderRadius: size > 40 ? 14 : 10,
        background: "#121214",
        border: "1px solid rgba(255,255,255,0.08)",
        overflow: "hidden",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <img src="/logo.png" alt="MALDEF" style={{ width: "100%", height: "100%", objectFit: "cover" }} />
    </div>
  );
}

export function BrandMark({ size = 36, className = "" }: { size?: number; className?: string }) {
  return (
    <div
      className={className}
      style={{
        width: size,
        height: size,
        minWidth: size,
        borderRadius: 10,
        background: "#ef4444",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        overflow: "hidden",
      }}
    >
      <img src="/logo.png" alt="MALDEF" style={{ width: "100%", height: "100%", objectFit: "cover" }} />
    </div>
  );
}

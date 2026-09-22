"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const res = await fetch("/api/auth/me");
        if (res.ok) {
          router.push("/dashboard");
        } else {
          router.push("/login");
        }
      } catch {
        router.push("/login");
      } finally {
        setChecking(false);
      }
    };
    checkAuth();
  }, [router]);

  if (checking) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#08080a]">
        <div className="text-center">
          <div className="w-20 h-20 rounded-xl bg-[#121214] border border-white/10 flex items-center justify-center mx-auto mb-4 overflow-hidden">
            <img src="/logo.png" alt="MALDEF" className="w-full h-full object-cover" />
          </div>
          <div className="w-12 h-12 border-2 border-[#ef4444] border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-[#71717a] font-mono text-sm tracking-widest">INITIALIZING MALDEF...</p>
        </div>
      </div>
    );
  }

  return null;
}

"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { checkAuth } from "@/lib/api";

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    // Login page is always accessible
    const loginPath = `${process.env.NEXT_PUBLIC_BASE_PATH || ""}/login`;
    if (pathname === "/login" || pathname === loginPath) {
      setReady(true);
      return;
    }

    checkAuth()
      .then(({ auth_enabled }) => {
        if (!auth_enabled) {
          setReady(true);
          return;
        }
        const token = localStorage.getItem("auth_token");
        if (!token) {
          router.replace(`${process.env.NEXT_PUBLIC_BASE_PATH || ""}/login`);
        } else {
          setReady(true);
        }
      })
      .catch(() => {
        // If auth check fails (server down), show content anyway
        setReady(true);
      });
  }, [pathname, router]);

  if (!ready) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-950">
        <p className="text-gray-400">Loading...</p>
      </div>
    );
  }

  return <>{children}</>;
}

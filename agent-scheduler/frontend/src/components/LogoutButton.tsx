"use client";

import { useEffect, useState } from "react";
import { checkAuth } from "@/lib/api";

export function LogoutButton() {
  const [authEnabled, setAuthEnabled] = useState(false);

  useEffect(() => {
    checkAuth()
      .then(({ auth_enabled }) => setAuthEnabled(auth_enabled))
      .catch(() => {});
  }, []);

  if (!authEnabled) return null;

  const handleLogout = () => {
    localStorage.removeItem("auth_token");
    window.location.href = `${process.env.NEXT_PUBLIC_BASE_PATH || ""}/login`;
  };

  return (
    <button
      onClick={handleLogout}
      className="px-3 py-2 rounded text-sm text-gray-400 hover:bg-gray-800 hover:text-white transition-colors text-left"
    >
      Logout
    </button>
  );
}

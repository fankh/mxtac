"use client";

import { useEffect, useRef } from "react";
import type { LogEntry } from "@/lib/types";

const levelColors: Record<string, string> = {
  INFO: "text-blue-300",
  WARNING: "text-yellow-300",
  ERROR: "text-red-300",
  DEBUG: "text-gray-400",
};

export function LogViewer({ logs }: { logs: LogEntry[] }) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div
      ref={containerRef}
      className="bg-gray-900 rounded-lg p-3 font-mono text-xs max-h-96 overflow-y-auto"
    >
      {logs.length === 0 && (
        <p className="text-gray-500">No logs yet</p>
      )}
      {logs.map((log) => (
        <div key={log.id} className="flex gap-2 py-0.5">
          <span className="text-gray-600 shrink-0">
            {log.timestamp
              ? new Date(log.timestamp).toLocaleTimeString()
              : "--:--:--"}
          </span>
          <span
            className={`shrink-0 w-14 ${levelColors[log.level] || "text-gray-400"}`}
          >
            [{log.level}]
          </span>
          <span className="text-gray-300 break-all">{log.message}</span>
        </div>
      ))}
    </div>
  );
}

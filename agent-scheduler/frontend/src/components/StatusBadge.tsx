"use client";

import type { TaskStatus, RunStatus } from "@/lib/types";

const statusStyles: Record<string, string> = {
  pending: "bg-gray-600 text-gray-200",
  running: "bg-blue-600 text-blue-100 animate-pulse",
  completed: "bg-green-600 text-green-100",
  failed: "bg-red-600 text-red-100",
  skipped: "bg-yellow-600 text-yellow-100",
  cancelled: "bg-gray-500 text-gray-200",
  timeout: "bg-orange-600 text-orange-100",
};

export function StatusBadge({
  status,
}: {
  status: TaskStatus | RunStatus;
}) {
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${statusStyles[status] || "bg-gray-600 text-gray-200"}`}
    >
      {status}
    </span>
  );
}

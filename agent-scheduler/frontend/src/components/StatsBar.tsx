"use client";

import type { Stats } from "@/lib/types";

export function StatsBar({ stats }: { stats: Stats | null }) {
  if (!stats) return null;

  const items = [
    { label: "Total", value: stats.total_tasks, color: "text-white" },
    { label: "Completed", value: stats.status_counts.completed || 0, color: "text-green-400" },
    { label: "Running", value: stats.status_counts.running || 0, color: "text-blue-400" },
    { label: "Failed", value: stats.status_counts.failed || 0, color: "text-red-400" },
    { label: "Pending", value: stats.status_counts.pending || 0, color: "text-gray-400" },
    { label: "Skipped", value: stats.status_counts.skipped || 0, color: "text-yellow-400" },
  ];

  const completedPct =
    stats.total_tasks > 0
      ? Math.round(((stats.status_counts.completed || 0) / stats.total_tasks) * 100)
      : 0;

  return (
    <div className="bg-gray-800 rounded-lg p-4 mb-6">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-white">Overview</h2>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">Scheduler:</span>
          <span
            className={`text-sm font-medium ${stats.scheduler.running ? (stats.scheduler.paused ? "text-yellow-400" : "text-green-400") : "text-red-400"}`}
          >
            {stats.scheduler.running
              ? stats.scheduler.paused
                ? "Paused"
                : "Running"
              : "Stopped"}
          </span>
        </div>
      </div>
      <div className="grid grid-cols-6 gap-4 mb-3">
        {items.map((item) => (
          <div key={item.label} className="text-center">
            <div className={`text-2xl font-bold ${item.color}`}>{item.value}</div>
            <div className="text-xs text-gray-500">{item.label}</div>
          </div>
        ))}
      </div>
      <div className="w-full bg-gray-700 rounded-full h-2">
        <div
          className="bg-green-500 h-2 rounded-full transition-all duration-500"
          style={{ width: `${completedPct}%` }}
        />
      </div>
      <div className="text-right text-xs text-gray-500 mt-1">{completedPct}% complete</div>
    </div>
  );
}

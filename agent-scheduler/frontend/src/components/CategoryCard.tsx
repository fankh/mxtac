"use client";

import { useState } from "react";
import Link from "next/link";
import type { CategoryInfo, TaskStatus } from "@/lib/types";

const statusColors: Record<TaskStatus, string> = {
  completed: "text-green-400",
  failed: "text-red-400",
  running: "text-blue-400",
  pending: "text-gray-400",
  skipped: "text-yellow-400",
  cancelled: "text-orange-400",
};

const badgeColors: Record<TaskStatus, string> = {
  completed: "bg-green-900 text-green-300",
  failed: "bg-red-900 text-red-300",
  running: "bg-blue-900 text-blue-300",
  pending: "bg-gray-700 text-gray-300",
  skipped: "bg-yellow-900 text-yellow-300",
  cancelled: "bg-orange-900 text-orange-300",
};

export function CategoryCard({ category }: { category: CategoryInfo }) {
  const [expanded, setExpanded] = useState(false);

  const completedPct =
    category.total > 0
      ? Math.round(
          ((category.completed + category.skipped) / category.total) * 100
        )
      : 0;

  const statusPills = [
    { key: "running" as const, count: category.running },
    { key: "completed" as const, count: category.completed },
    { key: "failed" as const, count: category.failed },
    { key: "pending" as const, count: category.pending },
    { key: "skipped" as const, count: category.skipped },
    { key: "cancelled" as const, count: category.cancelled },
  ].filter((s) => s.count > 0);

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-4 text-left"
      >
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-white truncate">
            {category.category}
          </h3>
          <span className="text-xs text-gray-400 ml-2 shrink-0">
            {category.total} tasks
          </span>
        </div>

        {/* Progress bar */}
        <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
          <div
            className="bg-green-500 h-2 rounded-full transition-all duration-500"
            style={{ width: `${completedPct}%` }}
          />
        </div>

        <div className="flex items-center justify-between">
          <span className="text-xs text-gray-400">{completedPct}%</span>
          <div className="flex gap-1 flex-wrap justify-end">
            {statusPills.map((s) => (
              <span
                key={s.key}
                className={`text-xs px-1.5 py-0.5 rounded ${statusColors[s.key]}`}
              >
                {s.count} {s.key}
              </span>
            ))}
          </div>
        </div>

        <div className="text-xs text-gray-500 mt-2">
          {expanded ? "Click to collapse" : "Click to expand"}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-gray-700 p-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 border-b border-gray-700">
                <th className="text-left pb-2">Title</th>
                <th className="text-left pb-2">Phase</th>
                <th className="text-left pb-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {category.tasks.map((task) => (
                <tr
                  key={task.id}
                  className="border-b border-gray-700/50 last:border-0"
                >
                  <td className="py-2 pr-2">
                    <Link
                      href={`/tasks/${task.id}`}
                      className="text-blue-400 hover:text-blue-300 hover:underline"
                    >
                      {task.title}
                    </Link>
                  </td>
                  <td className="py-2 pr-2 text-gray-400">{task.phase}</td>
                  <td className="py-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded ${badgeColors[task.status]}`}
                    >
                      {task.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

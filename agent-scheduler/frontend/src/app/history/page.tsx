"use client";

import { useCallback, useState } from "react";
import Link from "next/link";
import { StatusBadge } from "@/components/StatusBadge";
import { useApi } from "@/hooks/useApi";
import { useSSE } from "@/hooks/useSSE";
import { getRuns } from "@/lib/api";
import type { RunListResponse, RunStatus } from "@/lib/types";

const statusFilters: { label: string; value: string }[] = [
  { label: "All", value: "" },
  { label: "Running", value: "running" },
  { label: "Completed", value: "completed" },
  { label: "Failed", value: "failed" },
  { label: "Timeout", value: "timeout" },
  { label: "Cancelled", value: "cancelled" },
];

export default function HistoryPage() {
  const [statusFilter, setStatusFilter] = useState("");
  const [page, setPage] = useState(0);
  const limit = 50;

  const {
    data,
    loading,
    refetch,
  } = useApi<RunListResponse>(
    () =>
      getRuns({
        status: statusFilter || undefined,
        limit,
        offset: page * limit,
      }),
    [statusFilter, page]
  );

  const handleSSE = useCallback(
    (event: string) => {
      if (event === "task_update" || event === "run_update") {
        refetch();
      }
    },
    [refetch]
  );

  const { connected } = useSSE(handleSSE);

  const runs = data?.runs || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / limit);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold text-white">Run History</h1>
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${connected ? "bg-green-400" : "bg-red-400"}`}
          />
          <span className="text-xs text-gray-500">
            {connected ? "Live" : "Disconnected"}
          </span>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2 mb-4">
        {statusFilters.map((f) => (
          <button
            key={f.value}
            onClick={() => {
              setStatusFilter(f.value);
              setPage(0);
            }}
            className={`px-3 py-1.5 rounded text-sm transition-colors ${
              statusFilter === f.value
                ? "bg-blue-600 text-white"
                : "bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Summary */}
      <div className="text-sm text-gray-400 mb-3">
        {total} run{total !== 1 ? "s" : ""} total
        {statusFilter && ` (filtered: ${statusFilter})`}
      </div>

      {/* Table */}
      <div className="bg-gray-800/50 rounded-lg overflow-hidden">
        {loading && !data ? (
          <div className="p-8 text-center text-gray-500">Loading...</div>
        ) : runs.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No runs yet. The scheduler will create runs as it processes tasks.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-left">
                <th className="px-4 py-3 font-medium">Run</th>
                <th className="px-4 py-3 font-medium">Task</th>
                <th className="px-4 py-3 font-medium">Phase</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Duration</th>
                <th className="px-4 py-3 font-medium">Started</th>
                <th className="px-4 py-3 font-medium">Exit</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr
                  key={run.id}
                  className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                >
                  <td className="px-4 py-3">
                    <Link
                      href={`/tasks/${run.task_id}`}
                      className="text-blue-400 hover:text-blue-300"
                    >
                      #{run.id}
                    </Link>
                    <span className="text-gray-500 ml-1">
                      (attempt {run.attempt})
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      href={`/tasks/${run.task_id}`}
                      className="text-gray-200 hover:text-white"
                    >
                      {run.task_title}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {run.task_phase
                      ? run.task_phase.replace(/_/g, " ").replace(/^phase/, "Phase ")
                      : "-"}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={run.status as RunStatus} />
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {run.duration_seconds != null
                      ? `${run.duration_seconds.toFixed(1)}s`
                      : run.status === "running"
                        ? "..."
                        : "-"}
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {run.started_at
                      ? new Date(run.started_at).toLocaleString()
                      : "-"}
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {run.exit_code != null ? run.exit_code : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1.5 rounded text-sm bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Previous
          </button>
          <span className="text-sm text-gray-500">
            Page {page + 1} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            className="px-3 py-1.5 rounded text-sm bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

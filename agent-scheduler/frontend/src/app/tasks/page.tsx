"use client";

import { useCallback, useMemo, useState } from "react";
import Link from "next/link";
import { useApi } from "@/hooks/useApi";
import { useSSE } from "@/hooks/useSSE";
import {
  getTasks,
  getStats,
  getSchedulerSettings,
  triggerTask,
  skipTask,
  resetTask,
  cancelTask,
} from "@/lib/api";
import type { SchedulerSettings } from "@/lib/api";
import type { Task, TaskStatus, Stats, TaskListResponse } from "@/lib/types";
import { StatusBadge } from "@/components/StatusBadge";
import { TestBadge } from "@/components/TestBadge";
import { VerificationBadge } from "@/components/VerificationBadge";

const PAGE_SIZE = 50;

const ALL_STATUSES: TaskStatus[] = [
  "pending",
  "running",
  "completed",
  "failed",
  "skipped",
  "cancelled",
];

export default function TasksPage() {
  const [statusFilter, setStatusFilter] = useState("");
  const [phaseFilter, setPhaseFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [actionLoading, setActionLoading] = useState(false);

  const { data: settingsData } = useApi<SchedulerSettings>(
    () => getSchedulerSettings(),
    []
  );

  const { data: stats } = useApi<Stats>(() => getStats(), []);

  const {
    data: taskData,
    loading,
    refetch,
  } = useApi<TaskListResponse>(
    () =>
      getTasks({
        status: statusFilter || undefined,
        phase: phaseFilter || undefined,
        search: search || undefined,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      }),
    [statusFilter, phaseFilter, search, page]
  );

  const handleSSE = useCallback(
    (event: string) => {
      if (event === "task_update" || event === "scheduler" || event === "task_created") {
        refetch();
      }
    },
    [refetch]
  );

  const { connected } = useSSE(handleSSE);

  const phases = useMemo(() => {
    if (!stats?.phase_counts) return [];
    return Object.keys(stats.phase_counts).sort();
  }, [stats?.phase_counts]);

  // Extract categories from current task data
  const categories = useMemo(() => {
    if (!stats?.phase_counts) return [];
    // Collect unique categories from all tasks we've seen via stats
    // We'll use the phase_counts keys as a proxy; categories come from the API
    return [];
  }, [stats]);

  // Category list from actual tasks
  const categoryList = useMemo(() => {
    if (!taskData?.tasks) return [];
    const cats = new Set<string>();
    taskData.tasks.forEach((t) => {
      if (t.category) cats.add(t.category);
    });
    return Array.from(cats).sort();
  }, [taskData?.tasks]);

  const tasks = taskData?.tasks || [];
  const total = taskData?.total || 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  const allSelected = tasks.length > 0 && tasks.every((t) => selected.has(t.id));

  const toggleAll = () => {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(tasks.map((t) => t.id)));
    }
  };

  const toggleOne = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const bulkAction = async (
    action: (id: number) => Promise<unknown>,
    label: string
  ) => {
    if (selected.size === 0) return;
    if (!confirm(`${label} ${selected.size} task(s)?`)) return;
    setActionLoading(true);
    try {
      await Promise.all(Array.from(selected).map(action));
      setSelected(new Set());
      refetch();
    } catch (err) {
      console.error(`Failed to ${label}:`, err);
    } finally {
      setActionLoading(false);
    }
  };

  const resetFilters = () => {
    setStatusFilter("");
    setPhaseFilter("");
    setCategoryFilter("");
    setSearch("");
    setPage(0);
  };

  // Client-side category filter (since the API supports it but we add it for UX)
  const filteredTasks = categoryFilter
    ? tasks.filter((t) => t.category === categoryFilter)
    : tasks;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold text-white">All Tasks</h1>
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-400">{total} total</span>
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${connected ? "bg-green-400" : "bg-red-400"}`}
            />
            <span className="text-xs text-gray-500">
              {connected ? "Live" : "Disconnected"}
            </span>
          </div>
        </div>
      </div>

      {/* Status summary pills */}
      {stats && (
        <div className="flex gap-2 mb-4 flex-wrap">
          {ALL_STATUSES.map((s) => {
            const count = stats.status_counts[s] || 0;
            if (count === 0) return null;
            const isActive = statusFilter === s;
            return (
              <button
                key={s}
                onClick={() => {
                  setStatusFilter(isActive ? "" : s);
                  setPage(0);
                }}
                className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                  isActive
                    ? "bg-blue-600 text-white"
                    : s === "completed"
                      ? "bg-green-900/40 text-green-400 hover:bg-green-900/60"
                      : s === "failed"
                        ? "bg-red-900/40 text-red-400 hover:bg-red-900/60"
                        : s === "running"
                          ? "bg-yellow-900/40 text-yellow-400 hover:bg-yellow-900/60"
                          : s === "pending"
                            ? "bg-gray-700 text-gray-300 hover:bg-gray-600"
                            : "bg-gray-700 text-gray-400 hover:bg-gray-600"
                }`}
              >
                {s} ({count})
              </button>
            );
          })}
        </div>
      )}

      {/* Filters row */}
      <div className="flex gap-3 mb-4 items-center flex-wrap">
        <input
          type="text"
          placeholder="Search tasks..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(0);
          }}
          className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500 w-64"
        />
        <select
          value={phaseFilter}
          onChange={(e) => {
            setPhaseFilter(e.target.value);
            setPage(0);
          }}
          className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
        >
          <option value="">All phases</option>
          {phases.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        {categoryList.length > 0 && (
          <select
            value={categoryFilter}
            onChange={(e) => {
              setCategoryFilter(e.target.value);
              setPage(0);
            }}
            className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="">All categories</option>
            {categoryList.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        )}
        {(statusFilter || phaseFilter || categoryFilter || search) && (
          <button
            onClick={resetFilters}
            className="text-xs text-gray-400 hover:text-white transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Bulk actions */}
      {selected.size > 0 && (
        <div className="flex gap-2 mb-3 items-center">
          <span className="text-sm text-gray-400">
            {selected.size} selected:
          </span>
          <button
            onClick={() => bulkAction(triggerTask, "Trigger")}
            disabled={actionLoading}
            className="px-3 py-1 text-xs bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded transition-colors"
          >
            Trigger
          </button>
          <button
            onClick={() => bulkAction(resetTask, "Reset")}
            disabled={actionLoading}
            className="px-3 py-1 text-xs bg-yellow-600 hover:bg-yellow-500 disabled:opacity-50 text-white rounded transition-colors"
          >
            Reset
          </button>
          <button
            onClick={() => bulkAction(skipTask, "Skip")}
            disabled={actionLoading}
            className="px-3 py-1 text-xs bg-gray-600 hover:bg-gray-500 disabled:opacity-50 text-white rounded transition-colors"
          >
            Skip
          </button>
          <button
            onClick={() => bulkAction(cancelTask, "Cancel")}
            disabled={actionLoading}
            className="px-3 py-1 text-xs bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white rounded transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => setSelected(new Set())}
            className="text-xs text-gray-400 hover:text-white transition-colors ml-2"
          >
            Deselect all
          </button>
        </div>
      )}

      {/* Task table */}
      <div className="bg-gray-800/50 rounded-lg overflow-x-auto">
        {loading && !taskData ? (
          <p className="text-gray-500 p-6">Loading...</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-left">
                <th className="py-2 px-3 w-8">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleAll}
                    className="accent-blue-500"
                  />
                </th>
                <th className="py-2 px-3">ID</th>
                <th className="py-2 px-3">Title</th>
                <th className="py-2 px-3">Category</th>
                <th className="py-2 px-3">Phase</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Retries</th>
                <th className="py-2 px-3">Commit</th>
                <th className="py-2 px-3">Test</th>
                <th className="py-2 px-3">Verify</th>
                <th className="py-2 px-3">Updated</th>
              </tr>
            </thead>
            <tbody>
              {filteredTasks.map((task) => (
                <tr
                  key={task.id}
                  className={`border-b border-gray-800 hover:bg-gray-800/50 transition-colors ${
                    selected.has(task.id) ? "bg-blue-900/20" : ""
                  }`}
                  title={task.failure_reason || undefined}
                >
                  <td className="py-2 px-3">
                    <input
                      type="checkbox"
                      checked={selected.has(task.id)}
                      onChange={() => toggleOne(task.id)}
                      className="accent-blue-500"
                    />
                  </td>
                  <td className="py-2 px-3 text-gray-500 font-mono text-xs">
                    {task.task_id}
                  </td>
                  <td className="py-2 px-3">
                    <Link
                      href={`/tasks/${task.id}`}
                      className="text-blue-400 hover:text-blue-300 hover:underline"
                    >
                      {task.title}
                    </Link>
                    {task.failure_reason && (
                      <div className="text-xs text-red-400 mt-0.5 truncate max-w-md">
                        {task.failure_reason}
                      </div>
                    )}
                  </td>
                  <td className="py-2 px-3 text-gray-400 text-xs">
                    {task.category || "-"}
                  </td>
                  <td className="py-2 px-3 text-gray-400">{task.phase}</td>
                  <td className="py-2 px-3">
                    <StatusBadge status={task.status} />
                  </td>
                  <td className="py-2 px-3 text-gray-400">
                    {task.retry_count}/{task.max_retries}
                    {task.quality_retry_count > 0 && (
                      <span className="text-yellow-500 ml-1">
                        Q{task.quality_retry_count}
                      </span>
                    )}
                  </td>
                  <td className="py-2 px-3 font-mono text-xs">
                    {task.git_commit_sha ? (
                      settingsData?.github_repo_url ? (
                        <a
                          href={`${settingsData.github_repo_url}/commit/${task.git_commit_sha}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-green-400 hover:text-green-300 hover:underline"
                        >
                          {task.git_commit_sha.slice(0, 8)}
                        </a>
                      ) : (
                        <span className="text-green-400">
                          {task.git_commit_sha.slice(0, 8)}
                        </span>
                      )
                    ) : (
                      <span className="text-gray-600">-</span>
                    )}
                  </td>
                  <td className="py-2 px-3">
                    <TestBadge status={task.test_status} />
                  </td>
                  <td className="py-2 px-3">
                    <VerificationBadge status={task.verification_status} />
                  </td>
                  <td className="py-2 px-3 text-gray-500 text-xs whitespace-nowrap">
                    {task.updated_at
                      ? new Date(task.updated_at).toLocaleString()
                      : "-"}
                  </td>
                </tr>
              ))}
              {filteredTasks.length === 0 && (
                <tr>
                  <td
                    colSpan={11}
                    className="py-8 text-center text-gray-500"
                  >
                    No tasks found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <span className="text-sm text-gray-400">
            Page {page + 1} of {totalPages} ({total} tasks)
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(0)}
              disabled={page === 0}
              className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 disabled:opacity-30 text-gray-300 rounded transition-colors"
            >
              First
            </button>
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 disabled:opacity-30 text-gray-300 rounded transition-colors"
            >
              Prev
            </button>
            <button
              onClick={() =>
                setPage((p) => Math.min(totalPages - 1, p + 1))
              }
              disabled={page >= totalPages - 1}
              className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 disabled:opacity-30 text-gray-300 rounded transition-colors"
            >
              Next
            </button>
            <button
              onClick={() => setPage(totalPages - 1)}
              disabled={page >= totalPages - 1}
              className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 disabled:opacity-30 text-gray-300 rounded transition-colors"
            >
              Last
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

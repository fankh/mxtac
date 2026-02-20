"use client";

import Link from "next/link";
import { useState } from "react";
import type { Task, TaskStatus } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";

interface TaskTableProps {
  tasks: Task[];
  total: number;
  phases?: string[];
  onFilter?: (filters: {
    status?: string;
    phase?: string;
    search?: string;
  }) => void;
}

const statuses: TaskStatus[] = [
  "pending",
  "running",
  "completed",
  "failed",
  "skipped",
  "cancelled",
];

export function TaskTable({ tasks, total, phases, onFilter }: TaskTableProps) {
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [phaseFilter, setPhaseFilter] = useState<string>("");
  const [search, setSearch] = useState("");

  const applyFilters = (overrides: {
    status?: string;
    phase?: string;
    search?: string;
  }) => {
    const s = overrides.status ?? statusFilter;
    const p = overrides.phase ?? phaseFilter;
    const q = overrides.search ?? search;
    onFilter?.({
      status: s || undefined,
      phase: p || undefined,
      search: q || undefined,
    });
  };

  const handleStatusChange = (status: string) => {
    setStatusFilter(status);
    applyFilters({ status });
  };

  const handlePhaseChange = (phase: string) => {
    setPhaseFilter(phase);
    applyFilters({ phase });
  };

  const handleSearch = (q: string) => {
    setSearch(q);
    applyFilters({ search: q });
  };

  return (
    <div>
      <div className="flex gap-3 mb-4 items-center flex-wrap">
        <input
          type="text"
          placeholder="Search tasks..."
          value={search}
          onChange={(e) => handleSearch(e.target.value)}
          className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
        />
        <select
          value={statusFilter}
          onChange={(e) => handleStatusChange(e.target.value)}
          className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
        >
          <option value="">All statuses</option>
          {statuses.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        {phases && phases.length > 0 && (
          <select
            value={phaseFilter}
            onChange={(e) => handlePhaseChange(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="">All phases</option>
            {phases.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        )}
        <span className="text-sm text-gray-400 ml-auto">{total} tasks</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-700 text-gray-400 text-left">
              <th className="py-2 px-3">ID</th>
              <th className="py-2 px-3">Title</th>
              <th className="py-2 px-3">Category</th>
              <th className="py-2 px-3">Phase</th>
              <th className="py-2 px-3">Status</th>
              <th className="py-2 px-3">Retries</th>
              <th className="py-2 px-3">Commit</th>
              <th className="py-2 px-3">Updated</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((task) => (
              <tr
                key={task.id}
                className="border-b border-gray-800 hover:bg-gray-800/50 transition-colors"
              >
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
                </td>
                <td className="py-2 px-3 font-mono text-xs">
                  {task.git_commit_sha ? (
                    <span className="text-green-400">
                      {task.git_commit_sha.slice(0, 8)}
                    </span>
                  ) : (
                    <span className="text-gray-600">-</span>
                  )}
                </td>
                <td className="py-2 px-3 text-gray-500 text-xs">
                  {task.updated_at
                    ? new Date(task.updated_at).toLocaleString()
                    : "-"}
                </td>
              </tr>
            ))}
            {tasks.length === 0 && (
              <tr>
                <td colSpan={8} className="py-8 text-center text-gray-500">
                  No tasks found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

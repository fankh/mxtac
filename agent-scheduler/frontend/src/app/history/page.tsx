"use client";

import { useCallback, useState } from "react";
import Link from "next/link";
import { StatusBadge } from "@/components/StatusBadge";
import { TestBadge } from "@/components/TestBadge";
import { VerificationBadge } from "@/components/VerificationBadge";
import { useApi } from "@/hooks/useApi";
import { useSSE } from "@/hooks/useSSE";
import { getRuns, getAgentRunsList } from "@/lib/api";
import type {
  RunListResponse,
  RunStatus,
  AgentRunListResponse,
} from "@/lib/types";

const AGENT_NAMES = [
  "TaskCreatorAgent",
  "VerifierAgent",
  "TestAgent",
  "LintAgent",
  "IntegrationAgent",
  "SecurityAuditAgent",
];

const runStatusFilters: { label: string; value: string }[] = [
  { label: "All", value: "" },
  { label: "Running", value: "running" },
  { label: "Completed", value: "completed" },
  { label: "Failed", value: "failed" },
  { label: "Timeout", value: "timeout" },
  { label: "Cancelled", value: "cancelled" },
];

const agentStatusFilters: { label: string; value: string }[] = [
  { label: "All", value: "" },
  { label: "Running", value: "running" },
  { label: "Completed", value: "completed" },
  { label: "Failed", value: "failed" },
];

type Tab = "tasks" | "agents";

export default function HistoryPage() {
  const [tab, setTab] = useState<Tab>("tasks");

  // Task runs state
  const [statusFilter, setStatusFilter] = useState("");
  const [page, setPage] = useState(0);
  const limit = 50;

  // Agent runs state
  const [agentNameFilter, setAgentNameFilter] = useState("");
  const [agentStatusFilter, setAgentStatusFilter] = useState("");
  const [agentPage, setAgentPage] = useState(0);

  const {
    data: taskRunData,
    loading: taskRunLoading,
    refetch: refetchTaskRuns,
  } = useApi<RunListResponse>(
    () =>
      getRuns({
        status: statusFilter || undefined,
        limit,
        offset: page * limit,
      }),
    [statusFilter, page]
  );

  const {
    data: agentRunData,
    loading: agentRunLoading,
    refetch: refetchAgentRuns,
  } = useApi<AgentRunListResponse>(
    () =>
      getAgentRunsList({
        agent_name: agentNameFilter || undefined,
        status: agentStatusFilter || undefined,
        limit,
        offset: agentPage * limit,
      }),
    [agentNameFilter, agentStatusFilter, agentPage]
  );

  const handleSSE = useCallback(
    (event: string) => {
      if (
        event === "task_update" ||
        event === "run_update" ||
        event === "agent_report"
      ) {
        refetchTaskRuns();
        refetchAgentRuns();
      }
    },
    [refetchTaskRuns, refetchAgentRuns]
  );

  const { connected } = useSSE(handleSSE);

  const taskRuns = taskRunData?.runs || [];
  const taskTotal = taskRunData?.total || 0;
  const taskTotalPages = Math.ceil(taskTotal / limit);

  const agentRuns = agentRunData?.runs || [];
  const agentTotal = agentRunData?.total || 0;
  const agentTotalPages = Math.ceil(agentTotal / limit);

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

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-gray-700">
        <button
          onClick={() => setTab("tasks")}
          className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
            tab === "tasks"
              ? "border-blue-500 text-white"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          Task Runs ({taskTotal})
        </button>
        <button
          onClick={() => setTab("agents")}
          className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
            tab === "agents"
              ? "border-blue-500 text-white"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          Agent Runs ({agentTotal})
        </button>
      </div>

      {/* ===== Task Runs Tab ===== */}
      {tab === "tasks" && (
        <>
          {/* Filters */}
          <div className="flex gap-2 mb-4 flex-wrap">
            {runStatusFilters.map((f) => (
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

          <div className="text-sm text-gray-400 mb-3">
            {taskTotal} run{taskTotal !== 1 ? "s" : ""} total
            {statusFilter && ` (filtered: ${statusFilter})`}
          </div>

          <div className="bg-gray-800/50 rounded-lg overflow-hidden">
            {taskRunLoading && !taskRunData ? (
              <div className="p-8 text-center text-gray-500">Loading...</div>
            ) : taskRuns.length === 0 ? (
              <div className="p-8 text-center text-gray-500">
                No runs yet.
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700 text-gray-400 text-left">
                    <th className="px-4 py-3 font-medium">Run</th>
                    <th className="px-4 py-3 font-medium">Task</th>
                    <th className="px-4 py-3 font-medium">Phase</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">Verify</th>
                    <th className="px-4 py-3 font-medium">Test</th>
                    <th className="px-4 py-3 font-medium">Duration</th>
                    <th className="px-4 py-3 font-medium">Started</th>
                    <th className="px-4 py-3 font-medium">Exit</th>
                  </tr>
                </thead>
                <tbody>
                  {taskRuns.map((run) => (
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
                          ? run.task_phase
                              .replace(/_/g, " ")
                              .replace(/^phase/, "Phase ")
                          : "-"}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={run.status as RunStatus} />
                      </td>
                      <td className="px-4 py-3">
                        <VerificationBadge
                          status={run.verification_status}
                        />
                      </td>
                      <td className="px-4 py-3">
                        <TestBadge status={run.test_status} />
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {run.duration_seconds != null
                          ? `${run.duration_seconds.toFixed(1)}s`
                          : run.status === "running"
                            ? "..."
                            : "-"}
                      </td>
                      <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
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

          {taskTotalPages > 1 && (
            <div className="flex items-center justify-between mt-4">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="px-3 py-1.5 rounded text-sm bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <span className="text-sm text-gray-500">
                Page {page + 1} of {taskTotalPages}
              </span>
              <button
                onClick={() =>
                  setPage((p) => Math.min(taskTotalPages - 1, p + 1))
                }
                disabled={page >= taskTotalPages - 1}
                className="px-3 py-1.5 rounded text-sm bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      {/* ===== Agent Runs Tab ===== */}
      {tab === "agents" && (
        <>
          {/* Filters */}
          <div className="flex gap-3 mb-4 items-center flex-wrap">
            <select
              value={agentNameFilter}
              onChange={(e) => {
                setAgentNameFilter(e.target.value);
                setAgentPage(0);
              }}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
            >
              <option value="">All agents</option>
              {AGENT_NAMES.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
            {agentStatusFilters.map((f) => (
              <button
                key={f.value}
                onClick={() => {
                  setAgentStatusFilter(f.value);
                  setAgentPage(0);
                }}
                className={`px-3 py-1.5 rounded text-sm transition-colors ${
                  agentStatusFilter === f.value
                    ? "bg-blue-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200"
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          <div className="text-sm text-gray-400 mb-3">
            {agentTotal} run{agentTotal !== 1 ? "s" : ""} total
            {agentNameFilter && ` (agent: ${agentNameFilter})`}
            {agentStatusFilter && ` (status: ${agentStatusFilter})`}
          </div>

          <div className="bg-gray-800/50 rounded-lg overflow-hidden">
            {agentRunLoading && !agentRunData ? (
              <div className="p-8 text-center text-gray-500">Loading...</div>
            ) : agentRuns.length === 0 ? (
              <div className="p-8 text-center text-gray-500">
                No agent runs yet.
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700 text-gray-400 text-left">
                    <th className="px-4 py-3 font-medium">ID</th>
                    <th className="px-4 py-3 font-medium">Agent</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">Summary</th>
                    <th className="px-4 py-3 font-medium">Processed</th>
                    <th className="px-4 py-3 font-medium">Found</th>
                    <th className="px-4 py-3 font-medium">Started</th>
                    <th className="px-4 py-3 font-medium">Finished</th>
                  </tr>
                </thead>
                <tbody>
                  {agentRuns.map((run) => (
                    <tr
                      key={run.id}
                      className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                    >
                      <td className="px-4 py-3 text-gray-500 font-mono text-xs">
                        #{run.id}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-blue-400 text-xs font-medium">
                          {run.agent_name}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`text-xs font-medium px-2 py-0.5 rounded ${
                            run.status === "completed"
                              ? "bg-green-900/40 text-green-400"
                              : run.status === "failed"
                                ? "bg-red-900/40 text-red-400"
                                : run.status === "running"
                                  ? "bg-yellow-900/40 text-yellow-400"
                                  : "bg-gray-700 text-gray-400"
                          }`}
                        >
                          {run.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-300 text-xs max-w-md truncate">
                        {run.summary || "-"}
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {run.items_processed}
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {run.items_found}
                      </td>
                      <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                        {run.started_at
                          ? new Date(run.started_at).toLocaleString()
                          : "-"}
                      </td>
                      <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                        {run.finished_at
                          ? new Date(run.finished_at).toLocaleString()
                          : run.status === "running"
                            ? "..."
                            : "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {agentTotalPages > 1 && (
            <div className="flex items-center justify-between mt-4">
              <button
                onClick={() => setAgentPage((p) => Math.max(0, p - 1))}
                disabled={agentPage === 0}
                className="px-3 py-1.5 rounded text-sm bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <span className="text-sm text-gray-500">
                Page {agentPage + 1} of {agentTotalPages}
              </span>
              <button
                onClick={() =>
                  setAgentPage((p) =>
                    Math.min(agentTotalPages - 1, p + 1)
                  )
                }
                disabled={agentPage >= agentTotalPages - 1}
                className="px-3 py-1.5 rounded text-sm bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

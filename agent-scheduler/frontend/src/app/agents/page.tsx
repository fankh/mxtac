"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/useApi";
import { useSSE } from "@/hooks/useSSE";
import { getAgents, triggerAgent, getAgentRuns } from "@/lib/api";
import type { AgentInfo, AgentRunInfo, AgentsResponse } from "@/lib/types";

// New agents that support trigger + run history
const TRIGGERABLE_AGENTS = new Set([
  "TaskCreatorAgent",
  "VerifierAgent",
  "TestAgent",
  "LintAgent",
  "IntegrationAgent",
  "SecurityAuditAgent",
]);

function statusColor(status: AgentInfo["status"]) {
  switch (status) {
    case "running":
      return "bg-green-400";
    case "paused":
      return "bg-yellow-400";
    case "stopped":
      return "bg-red-400";
  }
}

function statusTextColor(status: AgentInfo["status"]) {
  switch (status) {
    case "running":
      return "text-green-400";
    case "paused":
      return "text-yellow-400";
    case "stopped":
      return "text-red-400";
  }
}

function formatTime(iso: string | null) {
  if (!iso) return "Never";
  const d = new Date(iso);
  return d.toLocaleTimeString();
}

function runStatusColor(status: string) {
  switch (status) {
    case "completed":
      return "text-green-400";
    case "failed":
      return "text-red-400";
    case "running":
      return "text-yellow-400";
    default:
      return "text-gray-400";
  }
}

export default function AgentsPage() {
  const {
    data: agentsData,
    loading,
    refetch,
  } = useApi<AgentsResponse>(() => getAgents(), []);

  const [triggering, setTriggering] = useState<string | null>(null);
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null);
  const [agentRuns, setAgentRuns] = useState<Record<string, AgentRunInfo[]>>({});
  const [loadingRuns, setLoadingRuns] = useState<string | null>(null);

  const handleSSE = useCallback(
    (event: string) => {
      if (event === "scheduler" || event === "agent_report" || event === "task_created") {
        refetch();
      }
    },
    [refetch]
  );

  const { connected } = useSSE(handleSSE);

  const handleTrigger = useCallback(async (agentName: string) => {
    setTriggering(agentName);
    try {
      await triggerAgent(agentName);
      refetch();
    } catch (err) {
      console.error("Failed to trigger agent:", err);
    } finally {
      setTriggering(null);
    }
  }, [refetch]);

  const handleToggleRuns = useCallback(async (agentName: string) => {
    if (expandedAgent === agentName) {
      setExpandedAgent(null);
      return;
    }
    setExpandedAgent(agentName);
    setLoadingRuns(agentName);
    try {
      const runs = await getAgentRuns(agentName);
      setAgentRuns((prev) => ({ ...prev, [agentName]: runs }));
    } catch (err) {
      console.error("Failed to fetch agent runs:", err);
    } finally {
      setLoadingRuns(null);
    }
  }, [expandedAgent]);

  const agents = agentsData?.agents || [];

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold text-white">Agents</h1>
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${connected ? "bg-green-400" : "bg-red-400"}`}
          />
          <span className="text-xs text-gray-500">
            {connected ? "Live" : "Disconnected"}
          </span>
        </div>
      </div>

      {loading && !agentsData ? (
        <p className="text-gray-500">Loading...</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {agents.map((agent) => (
            <div
              key={agent.name}
              className="bg-gray-800 rounded-lg p-5 border border-gray-700"
            >
              {/* Header */}
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-lg font-semibold text-white">
                  {agent.name}
                </h2>
                <div className="flex items-center gap-2">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${statusColor(agent.status)}`}
                  />
                  <span
                    className={`text-sm font-medium capitalize ${statusTextColor(agent.status)}`}
                  >
                    {agent.status}
                  </span>
                </div>
              </div>

              {/* Description */}
              <p className="text-sm text-gray-400 mb-4">{agent.description}</p>

              {/* Metrics */}
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Interval</span>
                  <span className="text-gray-300">
                    {agent.interval_seconds}s
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Cycles</span>
                  <span className="text-gray-300">{agent.action_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Last Action</span>
                  <span className="text-gray-300">
                    {formatTime(agent.last_action)}
                  </span>
                </div>
              </div>

              {/* Trigger + History buttons for new agents */}
              {TRIGGERABLE_AGENTS.has(agent.name) && (
                <div className="mt-4 flex gap-2">
                  <button
                    onClick={() => handleTrigger(agent.name)}
                    disabled={triggering === agent.name}
                    className="flex-1 px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:opacity-50 text-white rounded transition-colors"
                  >
                    {triggering === agent.name ? "Running..." : "Trigger"}
                  </button>
                  <button
                    onClick={() => handleToggleRuns(agent.name)}
                    className="px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition-colors"
                  >
                    {expandedAgent === agent.name ? "Hide" : "History"}
                  </button>
                </div>
              )}

              {/* Run History (expandable) */}
              {expandedAgent === agent.name && (
                <div className="mt-3 border-t border-gray-700 pt-3">
                  {loadingRuns === agent.name ? (
                    <p className="text-xs text-gray-500">Loading runs...</p>
                  ) : (agentRuns[agent.name] || []).length === 0 ? (
                    <p className="text-xs text-gray-500">No runs yet</p>
                  ) : (
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {(agentRuns[agent.name] || []).map((run) => (
                        <div
                          key={run.id}
                          className="text-xs bg-gray-900 rounded p-2"
                        >
                          <div className="flex justify-between">
                            <span className={runStatusColor(run.status)}>
                              {run.status}
                            </span>
                            <span className="text-gray-500">
                              {formatTime(run.started_at)}
                            </span>
                          </div>
                          {run.summary && (
                            <p className="text-gray-400 mt-1">{run.summary}</p>
                          )}
                          <div className="flex gap-3 mt-1 text-gray-500">
                            <span>Processed: {run.items_processed}</span>
                            <span>Found: {run.items_found}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

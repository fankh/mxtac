"use client";

import { useCallback, useState } from "react";
import { useApi } from "@/hooks/useApi";
import { useSSE } from "@/hooks/useSSE";
import {
  getAgents,
  triggerAgent,
  getAgentRuns,
  updateAgentInterval,
  getAgentConfig,
  updateAgentConfig,
} from "@/lib/api";
import type { AgentInfo, AgentRunInfo, AgentsResponse } from "@/lib/types";

// New agents that support trigger + run history + config
const TRIGGERABLE_AGENTS = new Set([
  "TaskCreatorAgent",
  "VerifierAgent",
  "TestAgent",
  "LintAgent",
  "IntegrationAgent",
  "SecurityAuditAgent",
]);

// Human-readable labels for config keys
const CONFIG_LABELS: Record<string, string> = {
  agent_task_creator_enabled: "Enabled",
  agent_task_creator_interval: "Interval (s)",
  agent_task_creator_max_tasks_per_cycle: "Max Tasks / Cycle",
  agent_task_creator_use_claude: "Use Claude",
  agent_verifier_enabled: "Enabled",
  agent_verifier_interval: "Interval (s)",
  agent_verifier_max_per_cycle: "Max / Cycle",
  agent_verifier_use_claude: "Use Claude",
  agent_verifier_fail_action: "Fail Action",
  agent_test_enabled: "Enabled",
  agent_test_interval: "Interval (s)",
  agent_test_fail_action: "Fail Action",
  agent_test_full_suite_every: "Full Suite Every N",
  agent_test_timeout: "Timeout (s)",
  agent_lint_enabled: "Enabled",
  agent_lint_interval: "Interval (s)",
  agent_lint_error_threshold: "Error Threshold",
  agent_integration_enabled: "Enabled",
  agent_integration_interval: "Interval (s)",
  agent_integration_smoke_url: "Smoke URL",
  agent_security_enabled: "Enabled",
  agent_security_interval: "Interval (s)",
  agent_security_bandit_skip: "Bandit Skip",
};

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
  const [agentRuns, setAgentRuns] = useState<Record<string, AgentRunInfo[]>>(
    {}
  );
  const [loadingRuns, setLoadingRuns] = useState<string | null>(null);
  const [editingInterval, setEditingInterval] = useState<string | null>(null);
  const [intervalValue, setIntervalValue] = useState("");

  // Config panel state
  const [configAgent, setConfigAgent] = useState<string | null>(null);
  const [configData, setConfigData] = useState<Record<string, unknown>>({});
  const [configDraft, setConfigDraft] = useState<Record<string, unknown>>({});
  const [configLoading, setConfigLoading] = useState(false);
  const [configSaving, setConfigSaving] = useState(false);

  const handleSSE = useCallback(
    (event: string) => {
      if (
        event === "scheduler" ||
        event === "agent_report" ||
        event === "task_created"
      ) {
        refetch();
      }
    },
    [refetch]
  );

  const { connected } = useSSE(handleSSE);

  const handleTrigger = useCallback(
    async (agentName: string) => {
      setTriggering(agentName);
      try {
        await triggerAgent(agentName);
        refetch();
      } catch (err) {
        console.error("Failed to trigger agent:", err);
      } finally {
        setTriggering(null);
      }
    },
    [refetch]
  );

  const handleIntervalSave = useCallback(
    async (agentName: string) => {
      const val = parseInt(intervalValue, 10);
      if (isNaN(val) || val < 10) return;
      try {
        await updateAgentInterval(agentName, val);
        refetch();
      } catch (err) {
        console.error("Failed to update interval:", err);
      }
      setEditingInterval(null);
    },
    [intervalValue, refetch]
  );

  const handleToggleRuns = useCallback(
    async (agentName: string) => {
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
    },
    [expandedAgent]
  );

  const handleToggleConfig = useCallback(
    async (agentName: string) => {
      if (configAgent === agentName) {
        setConfigAgent(null);
        return;
      }
      setConfigAgent(agentName);
      setConfigLoading(true);
      try {
        const data = await getAgentConfig(agentName);
        setConfigData(data);
        setConfigDraft({ ...data });
      } catch (err) {
        console.error("Failed to fetch agent config:", err);
      } finally {
        setConfigLoading(false);
      }
    },
    [configAgent]
  );

  const handleConfigSave = useCallback(async () => {
    if (!configAgent) return;
    setConfigSaving(true);
    try {
      // Only send changed values
      const changes: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(configDraft)) {
        if (v !== configData[k]) {
          changes[k] = v;
        }
      }
      if (Object.keys(changes).length > 0) {
        await updateAgentConfig(configAgent, changes);
        setConfigData({ ...configDraft });
        refetch();
      }
    } catch (err) {
      console.error("Failed to save agent config:", err);
    } finally {
      setConfigSaving(false);
    }
  }, [configAgent, configDraft, configData, refetch]);

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
              <p className="text-sm text-gray-400 mb-4">
                {agent.description}
              </p>

              {/* Metrics */}
              <div className="space-y-2 text-sm">
                <div className="flex justify-between items-center">
                  <span className="text-gray-500">Interval</span>
                  {editingInterval === agent.name ? (
                    <div className="flex items-center gap-1">
                      <input
                        type="number"
                        value={intervalValue}
                        onChange={(e) => setIntervalValue(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter")
                            handleIntervalSave(agent.name);
                          if (e.key === "Escape") setEditingInterval(null);
                        }}
                        className="bg-gray-700 border border-gray-600 rounded px-2 py-0.5 text-xs text-white w-20 focus:outline-none focus:border-blue-500"
                        autoFocus
                        min={10}
                      />
                      <span className="text-gray-500 text-xs">s</span>
                      <button
                        onClick={() => handleIntervalSave(agent.name)}
                        className="text-green-400 hover:text-green-300 text-xs px-1"
                      >
                        Save
                      </button>
                      <button
                        onClick={() => setEditingInterval(null)}
                        className="text-gray-500 hover:text-gray-400 text-xs px-1"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <span
                      className="text-gray-300 cursor-pointer hover:text-blue-400 transition-colors"
                      onClick={() => {
                        setEditingInterval(agent.name);
                        setIntervalValue(String(agent.interval_seconds));
                      }}
                      title="Click to edit"
                    >
                      {agent.interval_seconds}s
                    </span>
                  )}
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

              {/* Action buttons for triggerable agents */}
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
                    onClick={() => handleToggleConfig(agent.name)}
                    className={`px-3 py-1.5 text-sm rounded transition-colors ${
                      configAgent === agent.name
                        ? "bg-blue-600 text-white"
                        : "bg-gray-700 hover:bg-gray-600 text-gray-300"
                    }`}
                  >
                    Config
                  </button>
                  <button
                    onClick={() => handleToggleRuns(agent.name)}
                    className={`px-3 py-1.5 text-sm rounded transition-colors ${
                      expandedAgent === agent.name
                        ? "bg-blue-600 text-white"
                        : "bg-gray-700 hover:bg-gray-600 text-gray-300"
                    }`}
                  >
                    History
                  </button>
                </div>
              )}

              {/* Config Panel */}
              {configAgent === agent.name && (
                <div className="mt-3 border-t border-gray-700 pt-3">
                  {configLoading ? (
                    <p className="text-xs text-gray-500">Loading config...</p>
                  ) : (
                    <div className="space-y-2">
                      {Object.entries(configDraft).map(([key, value]) => {
                        const label = CONFIG_LABELS[key] || key;
                        const isBool = typeof value === "boolean";
                        const isSelect =
                          key.endsWith("_fail_action");
                        return (
                          <div
                            key={key}
                            className="flex items-center justify-between gap-2"
                          >
                            <label className="text-xs text-gray-400 shrink-0">
                              {label}
                            </label>
                            {isBool ? (
                              <button
                                onClick={() =>
                                  setConfigDraft((d) => ({
                                    ...d,
                                    [key]: !value,
                                  }))
                                }
                                className={`px-2 py-0.5 text-xs rounded transition-colors ${
                                  value
                                    ? "bg-green-600 text-white"
                                    : "bg-gray-600 text-gray-400"
                                }`}
                              >
                                {value ? "ON" : "OFF"}
                              </button>
                            ) : isSelect ? (
                              <select
                                value={String(value)}
                                onChange={(e) =>
                                  setConfigDraft((d) => ({
                                    ...d,
                                    [key]: e.target.value,
                                  }))
                                }
                                className="bg-gray-700 border border-gray-600 rounded px-2 py-0.5 text-xs text-white focus:outline-none focus:border-blue-500"
                              >
                                <option value="reset">reset</option>
                                <option value="mark">mark</option>
                              </select>
                            ) : (
                              <input
                                type={
                                  typeof value === "number" ? "number" : "text"
                                }
                                value={String(value)}
                                onChange={(e) =>
                                  setConfigDraft((d) => ({
                                    ...d,
                                    [key]:
                                      typeof value === "number"
                                        ? parseInt(e.target.value, 10) || 0
                                        : e.target.value,
                                  }))
                                }
                                className="bg-gray-700 border border-gray-600 rounded px-2 py-0.5 text-xs text-white w-24 focus:outline-none focus:border-blue-500"
                              />
                            )}
                          </div>
                        );
                      })}
                      <div className="flex gap-2 pt-1">
                        <button
                          onClick={handleConfigSave}
                          disabled={configSaving}
                          className="flex-1 px-3 py-1 text-xs bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white rounded transition-colors"
                        >
                          {configSaving ? "Saving..." : "Save Config"}
                        </button>
                        <button
                          onClick={() => setConfigDraft({ ...configData })}
                          className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition-colors"
                        >
                          Reset
                        </button>
                      </div>
                    </div>
                  )}
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

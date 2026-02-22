"use client";

import { useCallback } from "react";
import { useApi } from "@/hooks/useApi";
import { useSSE } from "@/hooks/useSSE";
import { getAgents } from "@/lib/api";
import type { AgentInfo, AgentsResponse } from "@/lib/types";

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

export default function AgentsPage() {
  const {
    data: agentsData,
    loading,
    refetch,
  } = useApi<AgentsResponse>(() => getAgents(), []);

  const handleSSE = useCallback(
    (event: string) => {
      if (event === "scheduler") {
        refetch();
      }
    },
    [refetch]
  );

  const { connected } = useSSE(handleSSE);

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
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

"use client";

import { useCallback, useMemo, useState } from "react";
import { StatsBar } from "@/components/StatsBar";
import { TaskTable } from "@/components/TaskTable";
import { useApi } from "@/hooks/useApi";
import { useSSE } from "@/hooks/useSSE";
import { getAgents, getSchedulerSettings, getStats, getTasks } from "@/lib/api";
import type { SchedulerSettings } from "@/lib/api";
import type { AgentsResponse, Stats, TaskListResponse } from "@/lib/types";

export default function DashboardPage() {
  const [filters, setFilters] = useState<{
    status?: string;
    phase?: string;
    search?: string;
  }>({});

  const { data: settingsData } = useApi<SchedulerSettings>(
    () => getSchedulerSettings(),
    []
  );

  const {
    data: stats,
    refetch: refetchStats,
  } = useApi<Stats>(() => getStats(), []);

  const {
    data: agentsData,
    refetch: refetchAgents,
  } = useApi<AgentsResponse>(() => getAgents(), []);

  const {
    data: taskData,
    loading: tasksLoading,
    refetch: refetchTasks,
  } = useApi<TaskListResponse>(
    () =>
      getTasks({
        status: filters.status,
        phase: filters.phase,
        search: filters.search,
        limit: 100,
      }),
    [filters.status, filters.phase, filters.search]
  );

  const handleSSE = useCallback(
    (event: string) => {
      if (event === "task_update" || event === "scheduler") {
        refetchStats();
        refetchTasks();
        refetchAgents();
      }
    },
    [refetchStats, refetchTasks, refetchAgents]
  );

  const { connected } = useSSE(handleSSE);

  // Extract sorted phase list from stats
  const phases = useMemo(() => {
    if (!stats?.phase_counts) return [];
    return Object.keys(stats.phase_counts).sort();
  }, [stats?.phase_counts]);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${connected ? "bg-green-400" : "bg-red-400"}`}
          />
          <span className="text-xs text-gray-500">
            {connected ? "Live" : "Disconnected"}
          </span>
        </div>
      </div>

      <StatsBar stats={stats} agents={agentsData?.agents} />

      <div className="bg-gray-800/50 rounded-lg p-4">
        <h2 className="text-lg font-semibold text-white mb-3">Tasks</h2>
        {tasksLoading && !taskData ? (
          <p className="text-gray-500">Loading...</p>
        ) : (
          <TaskTable
            tasks={taskData?.tasks || []}
            total={taskData?.total || 0}
            phases={phases}
            githubRepoUrl={settingsData?.github_repo_url}
            onFilter={setFilters}
          />
        )}
      </div>
    </div>
  );
}

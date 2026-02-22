"use client";

import type { AgentInfo, Stats } from "@/lib/types";

export function StatsBar({
  stats,
  agents,
}: {
  stats: Stats | null;
  agents?: AgentInfo[];
}) {
  if (!stats) return null;

  const completed = stats.status_counts.completed || 0;
  const failed = stats.status_counts.failed || 0;
  const running = stats.status_counts.running || 0;
  const pending = stats.status_counts.pending || 0;
  const skipped = stats.status_counts.skipped || 0;
  const cancelled = stats.status_counts.cancelled || 0;
  const total = stats.total_tasks;

  const items = [
    { label: "Total", value: total, color: "text-white" },
    { label: "Completed", value: completed, color: "text-green-400" },
    { label: "Running", value: running, color: "text-blue-400" },
    { label: "Failed", value: failed, color: "text-red-400" },
    { label: "Pending", value: pending, color: "text-gray-400" },
    { label: "Skipped", value: skipped, color: "text-yellow-400" },
    { label: "Cancelled", value: cancelled, color: "text-orange-400" },
  ];

  const completedPct = total > 0 ? (completed / total) * 100 : 0;
  const failedPct = total > 0 ? (failed / total) * 100 : 0;
  const runningPct = total > 0 ? (running / total) * 100 : 0;

  // Phase progress
  const phases = Object.entries(stats.phase_counts || {}).sort(([a], [b]) =>
    a.localeCompare(b)
  );

  return (
    <div className="bg-gray-800 rounded-lg p-4 mb-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-white">Overview</h2>
        <div className="flex items-center gap-4">
          <span className="text-xs text-gray-500">
            Active: {stats.executor.running_count}
          </span>
          {agents && agents.length > 0 && (
            <div className="flex items-center gap-3">
              {agents.map((agent) => (
                <div key={agent.name} className="flex items-center gap-1.5">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      agent.status === "running"
                        ? "bg-green-400"
                        : agent.status === "paused"
                          ? "bg-yellow-400"
                          : "bg-red-400"
                    }`}
                  />
                  <span className="text-xs text-gray-400">{agent.name}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Status counts */}
      <div className="grid grid-cols-7 gap-3 mb-3">
        {items.map((item) => (
          <div key={item.label} className="text-center">
            <div className={`text-2xl font-bold ${item.color}`}>
              {item.value}
            </div>
            <div className="text-xs text-gray-500">{item.label}</div>
          </div>
        ))}
      </div>

      {/* Progress bar - multi-segment */}
      <div className="w-full bg-gray-700 rounded-full h-2.5 flex overflow-hidden">
        {completedPct > 0 && (
          <div
            className="bg-green-500 h-2.5 transition-all duration-500"
            style={{ width: `${completedPct}%` }}
          />
        )}
        {runningPct > 0 && (
          <div
            className="bg-blue-500 h-2.5 transition-all duration-500"
            style={{ width: `${runningPct}%` }}
          />
        )}
        {failedPct > 0 && (
          <div
            className="bg-red-500 h-2.5 transition-all duration-500"
            style={{ width: `${failedPct}%` }}
          />
        )}
      </div>
      <div className="flex justify-between text-xs text-gray-500 mt-1">
        <span>
          {Math.round(completedPct)}% complete
          {failedPct > 0 && ` · ${Math.round(failedPct)}% failed`}
        </span>
        <span>
          {completed + failed + skipped + cancelled} / {total} resolved
        </span>
      </div>

      {/* Quality counts */}
      {stats.quality && (
        <div className="mt-3 pt-3 border-t border-gray-700">
          <div className="text-xs text-gray-500 mb-2 font-medium">Quality</div>
          <div className="grid grid-cols-4 gap-3">
            <div className="text-center">
              <div className="text-lg font-bold text-green-400">
                {stats.quality.test_passed}
              </div>
              <div className="text-xs text-gray-500">Tests Passed</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-red-400">
                {stats.quality.test_failed}
              </div>
              <div className="text-xs text-gray-500">Tests Failed</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-green-400">
                {stats.quality.verification_passed}
              </div>
              <div className="text-xs text-gray-500">Verified</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-red-400">
                {stats.quality.verification_failed}
              </div>
              <div className="text-xs text-gray-500">Verify Failed</div>
            </div>
          </div>
        </div>
      )}

      {/* Phase progress */}
      {phases.length > 1 && (
        <div className="mt-4 pt-3 border-t border-gray-700">
          <div className="text-xs text-gray-500 mb-2 font-medium">
            Phase Progress
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            {phases.map(([phase, counts]) => {
              const phaseTotal = (counts.total as number) || 0;
              const phaseCompleted = (counts.completed as number) || 0;
              const phaseFailed = (counts.failed as number) || 0;
              const phaseRunning = (counts.running as number) || 0;
              const phasePct =
                phaseTotal > 0
                  ? Math.round((phaseCompleted / phaseTotal) * 100)
                  : 0;

              return (
                <div
                  key={phase}
                  className="bg-gray-900/50 rounded px-2.5 py-1.5"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-gray-400 truncate mr-1">
                      {phase}
                    </span>
                    <span className="text-xs text-gray-500 shrink-0">
                      {phaseCompleted}/{phaseTotal}
                    </span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-1 flex overflow-hidden">
                    {phaseCompleted > 0 && (
                      <div
                        className="bg-green-500 h-1"
                        style={{
                          width: `${(phaseCompleted / phaseTotal) * 100}%`,
                        }}
                      />
                    )}
                    {phaseRunning > 0 && (
                      <div
                        className="bg-blue-500 h-1"
                        style={{
                          width: `${(phaseRunning / phaseTotal) * 100}%`,
                        }}
                      />
                    )}
                    {phaseFailed > 0 && (
                      <div
                        className="bg-red-500 h-1"
                        style={{
                          width: `${(phaseFailed / phaseTotal) * 100}%`,
                        }}
                      />
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import type { PhaseInfo } from "@/lib/types";

export function PhaseCard({ phase }: { phase: PhaseInfo }) {
  const completedPct =
    phase.total > 0
      ? Math.round(((phase.completed + phase.skipped) / phase.total) * 100)
      : 0;

  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <h3 className="text-sm font-semibold text-white mb-2 truncate">
        {phase.phase}
      </h3>
      <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
        <div
          className="bg-green-500 h-2 rounded-full transition-all duration-500"
          style={{ width: `${completedPct}%` }}
        />
      </div>
      <div className="flex justify-between text-xs text-gray-400">
        <span>{completedPct}%</span>
        <span>
          {phase.completed}/{phase.total}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-1 mt-2 text-xs">
        {phase.running > 0 && (
          <span className="text-blue-400">{phase.running} running</span>
        )}
        {phase.failed > 0 && (
          <span className="text-red-400">{phase.failed} failed</span>
        )}
        {phase.pending > 0 && (
          <span className="text-gray-400">{phase.pending} pending</span>
        )}
      </div>
    </div>
  );
}

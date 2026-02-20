"use client";

import type { Run } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";

export function RunTimeline({ runs }: { runs: Run[] }) {
  if (runs.length === 0) {
    return <p className="text-gray-500 text-sm">No runs yet</p>;
  }

  return (
    <div className="space-y-3">
      {runs.map((run) => (
        <div
          key={run.id}
          className="bg-gray-800 rounded-lg p-3 border border-gray-700"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-white">
                Attempt #{run.attempt}
              </span>
              <StatusBadge status={run.status} />
            </div>
            <div className="text-xs text-gray-500">
              {run.duration_seconds != null
                ? `${run.duration_seconds.toFixed(1)}s`
                : "-"}
            </div>
          </div>
          <div className="text-xs text-gray-400 space-y-1">
            {run.pid && <div>PID: {run.pid}</div>}
            {run.exit_code != null && <div>Exit code: {run.exit_code}</div>}
            {run.started_at && (
              <div>Started: {new Date(run.started_at).toLocaleString()}</div>
            )}
            {run.finished_at && (
              <div>Finished: {new Date(run.finished_at).toLocaleString()}</div>
            )}
          </div>
          {run.stdout && (
            <details className="mt-2">
              <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-300">
                stdout
              </summary>
              <pre className="mt-1 p-2 bg-gray-900 rounded text-xs text-green-300 overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap">
                {run.stdout}
              </pre>
            </details>
          )}
          {run.stderr && (
            <details className="mt-2">
              <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-300">
                stderr
              </summary>
              <pre className="mt-1 p-2 bg-gray-900 rounded text-xs text-red-300 overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap">
                {run.stderr}
              </pre>
            </details>
          )}
        </div>
      ))}
    </div>
  );
}

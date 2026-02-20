"use client";

import { useState } from "react";
import type { TaskStatus } from "@/lib/types";
import { triggerTask, skipTask, resetTask, cancelTask } from "@/lib/api";

interface TaskActionsProps {
  taskId: number;
  status: TaskStatus;
  onAction?: () => void;
}

export function TaskActions({ taskId, status, onAction }: TaskActionsProps) {
  const [loading, setLoading] = useState(false);

  const handleAction = async (action: () => Promise<unknown>) => {
    setLoading(true);
    try {
      await action();
      onAction?.();
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : "Action failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex gap-2 flex-wrap">
      {(status === "pending" || status === "failed") && (
        <button
          onClick={() => handleAction(() => triggerTask(taskId))}
          disabled={loading}
          className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
        >
          Trigger
        </button>
      )}
      {(status === "pending" || status === "failed") && (
        <button
          onClick={() => handleAction(() => skipTask(taskId))}
          disabled={loading}
          className="px-3 py-1.5 bg-yellow-600 hover:bg-yellow-500 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
        >
          Skip
        </button>
      )}
      {status === "running" && (
        <button
          onClick={() => handleAction(() => cancelTask(taskId))}
          disabled={loading}
          className="px-3 py-1.5 bg-red-600 hover:bg-red-500 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
        >
          Cancel
        </button>
      )}
      {(status === "completed" ||
        status === "failed" ||
        status === "skipped" ||
        status === "cancelled") && (
        <button
          onClick={() => handleAction(() => resetTask(taskId))}
          disabled={loading}
          className="px-3 py-1.5 bg-gray-600 hover:bg-gray-500 disabled:bg-gray-700 text-white text-sm rounded transition-colors"
        >
          Reset
        </button>
      )}
    </div>
  );
}

"use client";

import { use, useCallback } from "react";
import Link from "next/link";
import { RunTimeline } from "@/components/RunTimeline";
import { StatusBadge } from "@/components/StatusBadge";
import { TestBadge } from "@/components/TestBadge";
import { VerificationBadge } from "@/components/VerificationBadge";
import { TaskActions } from "@/components/TaskActions";
import { useApi } from "@/hooks/useApi";
import { useSSE } from "@/hooks/useSSE";
import { getTask, getTaskRuns } from "@/lib/api";
import type { Run, Task } from "@/lib/types";

export default function TaskDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const taskId = parseInt(id, 10);

  const {
    data: task,
    loading: taskLoading,
    refetch: refetchTask,
  } = useApi<Task>(() => getTask(taskId), [taskId]);

  const {
    data: runs,
    refetch: refetchRuns,
  } = useApi<Run[]>(() => getTaskRuns(taskId), [taskId]);

  const handleSSE = useCallback(
    (event: string, data: unknown) => {
      if (event === "task_update") {
        const d = data as { id?: number };
        if (d.id === taskId) {
          refetchTask();
          refetchRuns();
        }
      }
      if (event === "run_update") {
        const d = data as { task_id?: number };
        if (d.task_id === taskId) {
          refetchRuns();
        }
      }
    },
    [taskId, refetchTask, refetchRuns]
  );

  useSSE(handleSSE);

  if (taskLoading || !task) {
    return <p className="text-gray-500">Loading...</p>;
  }

  return (
    <div>
      <div className="mb-4">
        <Link
          href="/"
          className="text-sm text-gray-400 hover:text-gray-300"
        >
          &larr; Back to Dashboard
        </Link>
      </div>

      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white mb-1">{task.title}</h1>
          <div className="flex items-center gap-3 text-sm text-gray-400">
            <span className="font-mono">{task.task_id}</span>
            <span>{task.phase}</span>
            <StatusBadge status={task.status} />
          </div>
        </div>
        <TaskActions
          taskId={task.id}
          status={task.status}
          onAction={() => {
            refetchTask();
            refetchRuns();
          }}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Task Details */}
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h2 className="text-lg font-semibold text-white mb-3">Details</h2>
          <dl className="space-y-2 text-sm">
            <div>
              <dt className="text-gray-500">Category</dt>
              <dd className="text-gray-200">{task.category || "-"}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Priority</dt>
              <dd className="text-gray-200">{task.priority}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Working Directory</dt>
              <dd className="text-gray-200 font-mono text-xs">
                {task.working_directory || "-"}
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">Dependencies</dt>
              <dd className="text-gray-200">
                {task.depends_on.length > 0
                  ? task.depends_on.join(", ")
                  : "None"}
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">Model</dt>
              <dd className="text-gray-200">{task.model || "default"}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Retries</dt>
              <dd className={task.retry_count >= task.max_retries ? "text-red-400 font-medium" : "text-gray-200"}>
                {task.retry_count}/{task.max_retries}
                {task.retry_count >= task.max_retries && task.max_retries > 0 && (
                  <span className="ml-2 text-xs text-red-500">(exhausted)</span>
                )}
              </dd>
            </div>
            {task.quality_retry_count > 0 && (
              <div>
                <dt className="text-gray-500">Quality Retries</dt>
                <dd className="text-yellow-400 font-medium">
                  {task.quality_retry_count}
                </dd>
              </div>
            )}
            {task.failure_reason && (
              <div>
                <dt className="text-gray-500">Failure Reason</dt>
                <dd className="text-red-400 text-sm whitespace-pre-wrap">
                  {task.failure_reason}
                </dd>
              </div>
            )}
            {task.acceptance_criteria && (
              <div>
                <dt className="text-gray-500">Acceptance Criteria</dt>
                <dd className="text-gray-200 whitespace-pre-wrap">
                  {task.acceptance_criteria}
                </dd>
              </div>
            )}
          </dl>
        </div>

        {/* Prompt */}
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h2 className="text-lg font-semibold text-white mb-3">Prompt</h2>
          <pre className="text-sm text-gray-300 whitespace-pre-wrap bg-gray-900 p-3 rounded max-h-96 overflow-y-auto">
            {task.prompt || "No prompt"}
          </pre>
        </div>
      </div>

      {/* Test Results */}
      {task.test_status && (
        <div className="mt-6">
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center gap-3 mb-3">
              <h2 className="text-lg font-semibold text-white">Test Results</h2>
              <TestBadge status={task.test_status} />
            </div>
            {task.test_output && (
              <details open={task.test_status === "failed"}>
                <summary className="text-sm text-gray-400 cursor-pointer hover:text-gray-300 mb-2">
                  Test Output
                </summary>
                <pre className="text-xs text-gray-300 whitespace-pre-wrap bg-gray-900 p-3 rounded max-h-96 overflow-y-auto">
                  {task.test_output}
                </pre>
              </details>
            )}
          </div>
        </div>
      )}

      {/* Verification Results */}
      {task.verification_status && (
        <div className="mt-6">
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center gap-3 mb-3">
              <h2 className="text-lg font-semibold text-white">Verification Results</h2>
              <VerificationBadge status={task.verification_status} />
            </div>
            {task.verification_output && (
              <details open={task.verification_status === "failed"}>
                <summary className="text-sm text-gray-400 cursor-pointer hover:text-gray-300 mb-2">
                  Verification Output
                </summary>
                {(() => {
                  try {
                    const checks = JSON.parse(task.verification_output);
                    if (Array.isArray(checks)) {
                      return (
                        <div className="space-y-2">
                          {checks.map((check: { name?: string; status?: string; message?: string }, i: number) => (
                            <div
                              key={i}
                              className={`text-xs p-2 rounded ${
                                check.status === "passed"
                                  ? "bg-green-900/30 border border-green-800"
                                  : check.status === "failed"
                                    ? "bg-red-900/30 border border-red-800"
                                    : "bg-gray-900 border border-gray-700"
                              }`}
                            >
                              <span className="font-medium text-gray-200">
                                {check.name || `Check ${i + 1}`}
                              </span>
                              {check.status && (
                                <span
                                  className={`ml-2 ${
                                    check.status === "passed" ? "text-green-400" : "text-red-400"
                                  }`}
                                >
                                  [{check.status}]
                                </span>
                              )}
                              {check.message && (
                                <p className="text-gray-400 mt-1">{check.message}</p>
                              )}
                            </div>
                          ))}
                        </div>
                      );
                    }
                  } catch {
                    // Not JSON, fall through to raw text
                  }
                  return (
                    <pre className="text-xs text-gray-300 whitespace-pre-wrap bg-gray-900 p-3 rounded max-h-96 overflow-y-auto">
                      {task.verification_output}
                    </pre>
                  );
                })()}
              </details>
            )}
          </div>
        </div>
      )}

      {/* Run History */}
      <div className="mt-6">
        <h2 className="text-lg font-semibold text-white mb-3">Run History</h2>
        <RunTimeline runs={runs || []} />
      </div>
    </div>
  );
}

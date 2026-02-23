"use client";

import { useState, useCallback, useEffect } from "react";
import { useApi } from "@/hooks/useApi";
import { useSSE } from "@/hooks/useSSE";
import {
  controlScheduler,
  getSchedulerSettings,
  getSchedulerStatus,
  loadTasks,
  updateSchedulerSettings,
} from "@/lib/api";

export default function SettingsPage() {
  const {
    data: schedulerStatus,
    refetch,
  } = useApi(() => getSchedulerStatus(), []);

  const { data: currentSettings } = useApi(() => getSchedulerSettings(), []);

  const [maxConcurrent, setMaxConcurrent] = useState("");
  const [spawnDelay, setSpawnDelay] = useState("");
  const [taskTimeout, setTaskTimeout] = useState("");
  const [model, setModel] = useState("");
  const [retryMax, setRetryMax] = useState("");
  const [retryBackoff, setRetryBackoff] = useState("");
  const [githubRepoUrl, setGithubRepoUrl] = useState("");
  const [testCommand, setTestCommand] = useState("");
  const [testTimeout, setTestTimeout] = useState("");
  const [qualityRetryMax, setQualityRetryMax] = useState("");
  const [taskPath, setTaskPath] = useState("");
  const [loadResult, setLoadResult] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  // Populate form with current backend values once loaded
  useEffect(() => {
    if (currentSettings) {
      setMaxConcurrent(String(currentSettings.max_concurrent));
      setSpawnDelay(String(currentSettings.spawn_delay));
      setTaskTimeout(String(currentSettings.task_timeout));
      setModel(currentSettings.model);
      setRetryMax(String(currentSettings.retry_max));
      setRetryBackoff(String(currentSettings.retry_backoff));
      setGithubRepoUrl(currentSettings.github_repo_url);
      setTestCommand(currentSettings.test_command);
      setTestTimeout(String(currentSettings.test_timeout));
      setQualityRetryMax(String(currentSettings.quality_retry_max));
    }
  }, [currentSettings]);

  const handleSSE = useCallback(
    (event: string) => {
      if (event === "scheduler") refetch();
    },
    [refetch]
  );
  useSSE(handleSSE);

  const handleControl = async (action: string) => {
    setActionLoading(true);
    try {
      await controlScheduler(action);
      refetch();
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : "Failed");
    } finally {
      setActionLoading(false);
    }
  };

  const handleSettingsUpdate = async () => {
    try {
      await updateSchedulerSettings({
        max_concurrent: parseInt(maxConcurrent, 10),
        spawn_delay: parseInt(spawnDelay, 10),
        task_timeout: parseInt(taskTimeout, 10),
        model,
        retry_max: parseInt(retryMax, 10),
        retry_backoff: parseInt(retryBackoff, 10),
        github_repo_url: githubRepoUrl,
        test_command: testCommand,
        test_timeout: parseInt(testTimeout, 10),
        quality_retry_max: parseInt(qualityRetryMax, 10),
      });
      alert("Settings updated");
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : "Failed");
    }
  };

  const handleLoadTasks = async () => {
    if (!taskPath.trim()) return;
    setLoadResult(null);
    try {
      const result = (await loadTasks(taskPath.trim())) as {
        created: number;
        skipped: number;
        total_parsed: number;
      };
      setLoadResult(
        `Loaded: ${result.created} created, ${result.skipped} skipped (${result.total_parsed} parsed)`
      );
    } catch (e: unknown) {
      setLoadResult(e instanceof Error ? e.message : "Failed to load");
    }
  };

  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-bold text-white mb-6">Settings</h1>

      {/* Scheduler Control */}
      <section className="bg-gray-800 rounded-lg p-4 border border-gray-700 mb-6">
        <h2 className="text-lg font-semibold text-white mb-3">
          Scheduler Control
        </h2>
        <div className="flex items-center gap-3 mb-4">
          <span className="text-sm text-gray-400">Status:</span>
          <span
            className={`text-sm font-medium ${
              schedulerStatus?.running
                ? schedulerStatus?.paused
                  ? "text-yellow-400"
                  : "text-green-400"
                : "text-red-400"
            }`}
          >
            {schedulerStatus?.running
              ? schedulerStatus?.paused
                ? "Paused"
                : "Running"
              : "Stopped"}
          </span>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleControl("start")}
            disabled={actionLoading || schedulerStatus?.running}
            className="px-4 py-2 bg-green-600 hover:bg-green-500 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
          >
            Start
          </button>
          <button
            onClick={() => handleControl("pause")}
            disabled={
              actionLoading ||
              !schedulerStatus?.running ||
              schedulerStatus?.paused
            }
            className="px-4 py-2 bg-yellow-600 hover:bg-yellow-500 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
          >
            Pause
          </button>
          <button
            onClick={() => handleControl("resume")}
            disabled={actionLoading || !schedulerStatus?.paused}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
          >
            Resume
          </button>
          <button
            onClick={() => handleControl("stop")}
            disabled={actionLoading || !schedulerStatus?.running}
            className="px-4 py-2 bg-red-600 hover:bg-red-500 disabled:bg-gray-600 text-white text-sm rounded transition-colors"
          >
            Stop
          </button>
        </div>
      </section>

      {/* Scheduler Settings */}
      <section className="bg-gray-800 rounded-lg p-4 border border-gray-700 mb-6">
        <h2 className="text-lg font-semibold text-white mb-3">
          Scheduler Settings
        </h2>
        <div className="space-y-3">
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Max Concurrent Tasks
            </label>
            <input
              type="number"
              value={maxConcurrent}
              onChange={(e) => setMaxConcurrent(e.target.value)}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white w-32 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Spawn Delay (seconds)
            </label>
            <input
              type="number"
              value={spawnDelay}
              onChange={(e) => setSpawnDelay(e.target.value)}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white w-32 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Task Timeout (seconds)
            </label>
            <input
              type="number"
              value={taskTimeout}
              onChange={(e) => setTaskTimeout(e.target.value)}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white w-32 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Claude Model
            </label>
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
            >
              <option value="sonnet">Sonnet</option>
              <option value="opus">Opus</option>
              <option value="haiku">Haiku</option>
            </select>
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Max Retries
            </label>
            <input
              type="number"
              value={retryMax}
              onChange={(e) => setRetryMax(e.target.value)}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white w-32 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Retry Backoff (seconds)
            </label>
            <input
              type="number"
              value={retryBackoff}
              onChange={(e) => setRetryBackoff(e.target.value)}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white w-32 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              GitHub Repo URL
            </label>
            <input
              type="text"
              value={githubRepoUrl}
              onChange={(e) => setGithubRepoUrl(e.target.value)}
              placeholder="https://github.com/user/repo"
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white w-full placeholder-gray-400 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Test Command
            </label>
            <input
              type="text"
              value={testCommand}
              onChange={(e) => setTestCommand(e.target.value)}
              placeholder="e.g. pytest tests/ (empty = disabled)"
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white w-full placeholder-gray-400 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Test Timeout (seconds)
            </label>
            <input
              type="number"
              value={testTimeout}
              onChange={(e) => setTestTimeout(e.target.value)}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white w-32 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Quality Retry Max
            </label>
            <input
              type="number"
              value={qualityRetryMax}
              onChange={(e) => setQualityRetryMax(e.target.value)}
              className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white w-32 focus:outline-none focus:border-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">
              Max retries after verification/test failure before permanently failed
            </p>
          </div>
          <button
            onClick={handleSettingsUpdate}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded transition-colors"
          >
            Update Settings
          </button>
        </div>
      </section>

      {/* Task Loading */}
      <section className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <h2 className="text-lg font-semibold text-white mb-3">Load Tasks</h2>
        <div className="flex gap-2 mb-2">
          <input
            type="text"
            placeholder="Path to YAML file or directory..."
            value={taskPath}
            onChange={(e) => setTaskPath(e.target.value)}
            className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={handleLoadTasks}
            className="px-4 py-2 bg-green-600 hover:bg-green-500 text-white text-sm rounded transition-colors"
          >
            Load
          </button>
        </div>
        {loadResult && (
          <p className="text-sm text-gray-300 mt-2">{loadResult}</p>
        )}
      </section>
    </div>
  );
}

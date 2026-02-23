import type { AgentRunInfo, AgentsResponse, CategoryInfo, PhaseInfo, Run, RunListResponse, Stats, Task, TaskListResponse } from "./types";

const BASE = "/api";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("auth_token");
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string>),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE}${url}`, { ...init, headers });

  if (res.status === 401) {
    localStorage.removeItem("auth_token");
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API error ${res.status}: ${text}`);
  }
  return res.json();
}

// Auth (bypass fetchJson since these are pre-auth)
export const checkAuth = async (): Promise<{ auth_enabled: boolean }> => {
  const res = await fetch(`${BASE}/auth/check`);
  return res.json();
};

export const login = async (password: string): Promise<{ token: string }> => {
  const res = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Login failed: ${text}`);
  }
  return res.json();
};

// Stats
export const getStats = () => fetchJson<Stats>("/stats");

// Agents
export const getAgents = () => fetchJson<AgentsResponse>("/agents");

export const triggerAgent = (name: string) =>
  fetchJson(`/agents/${name}/trigger`, { method: "POST" });

export const getAgentRuns = (name: string, limit = 20) =>
  fetchJson<AgentRunInfo[]>(`/agents/${name}/runs?limit=${limit}`);

// Tasks
export const getTasks = (params?: {
  status?: string;
  phase?: string;
  search?: string;
  limit?: number;
  offset?: number;
}) => {
  const sp = new URLSearchParams();
  if (params?.status) sp.set("status", params.status);
  if (params?.phase) sp.set("phase", params.phase);
  if (params?.search) sp.set("search", params.search);
  if (params?.limit) sp.set("limit", String(params.limit));
  if (params?.offset) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  return fetchJson<TaskListResponse>(`/tasks${qs ? `?${qs}` : ""}`);
};

export const getTask = (id: number) => fetchJson<Task>(`/tasks/${id}`);

export const getTaskRuns = (id: number) => fetchJson<Run[]>(`/tasks/${id}/runs`);

// Task Actions
export const triggerTask = (id: number) =>
  fetchJson(`/tasks/${id}/trigger`, { method: "POST" });

export const skipTask = (id: number) =>
  fetchJson(`/tasks/${id}/skip`, { method: "POST" });

export const resetTask = (id: number) =>
  fetchJson(`/tasks/${id}/reset`, { method: "POST" });

export const cancelTask = (id: number) =>
  fetchJson(`/tasks/${id}/cancel`, { method: "POST" });

// Task Loading
export const loadTasks = (path: string) =>
  fetchJson("/tasks/load", {
    method: "POST",
    body: JSON.stringify({ path }),
  });

// Scheduler
export const getSchedulerStatus = () =>
  fetchJson<{ running: boolean; paused: boolean }>("/scheduler/status");

export interface SchedulerSettings {
  max_concurrent: number;
  spawn_delay: number;
  task_timeout: number;
  model: string;
  retry_max: number;
  retry_backoff: number;
  github_repo_url: string;
  test_command: string;
  test_timeout: number;
  quality_retry_max: number;
}

export const getSchedulerSettings = () =>
  fetchJson<SchedulerSettings>("/scheduler/settings");

export const controlScheduler = (action: string) =>
  fetchJson("/scheduler/control", {
    method: "POST",
    body: JSON.stringify({ action }),
  });

export const updateSchedulerSettings = (settings: {
  max_concurrent?: number;
  spawn_delay?: number;
  task_timeout?: number;
  model?: string;
  retry_max?: number;
  retry_backoff?: number;
  github_repo_url?: string;
  test_command?: string;
  test_timeout?: number;
  quality_retry_max?: number;
}) =>
  fetchJson("/scheduler/settings", {
    method: "PUT",
    body: JSON.stringify(settings),
  });

// Phases
export const getPhases = () => fetchJson<PhaseInfo[]>("/phases");

// Categories
export const getCategories = () => fetchJson<CategoryInfo[]>("/categories");

// Runs (history)
export const getRuns = (params?: {
  status?: string;
  limit?: number;
  offset?: number;
}) => {
  const sp = new URLSearchParams();
  if (params?.status) sp.set("status", params.status);
  if (params?.limit) sp.set("limit", String(params.limit));
  if (params?.offset) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  return fetchJson<RunListResponse>(`/runs${qs ? `?${qs}` : ""}`);
};

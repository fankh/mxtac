export type TaskStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "skipped"
  | "cancelled";

export type RunStatus =
  | "running"
  | "completed"
  | "failed"
  | "timeout"
  | "cancelled";

export interface Task {
  id: number;
  task_id: string;
  title: string;
  category: string;
  phase: string;
  priority: number;
  status: TaskStatus;
  prompt: string;
  depends_on: string[];
  working_directory: string;
  target_files: string[];
  acceptance_criteria: string;
  retry_count: number;
  max_retries: number;
  git_commit_sha: string | null;
  model: string | null;
  allowed_tools: string[];
  created_at: string | null;
  updated_at: string | null;
}

export interface Run {
  id: number;
  task_id: number;
  attempt: number;
  status: RunStatus;
  exit_code: number | null;
  pid: number | null;
  stdout: string;
  stderr: string;
  git_diff: string;
  files_changed: string[];
  duration_seconds: number | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface LogEntry {
  id: number;
  run_id: number;
  level: string;
  message: string;
  timestamp: string | null;
}

export interface PhaseInfo {
  phase: string;
  total: number;
  completed: number;
  failed: number;
  running: number;
  pending: number;
  skipped: number;
  cancelled: number;
}

export interface Stats {
  total_tasks: number;
  status_counts: Record<string, number>;
  phase_counts: Record<string, Record<string, number>>;
  scheduler: {
    running: boolean;
    paused: boolean;
  };
  executor: {
    running_count: number;
  };
}

export interface CategoryInfo {
  category: string;
  total: number;
  completed: number;
  failed: number;
  running: number;
  pending: number;
  skipped: number;
  cancelled: number;
  tasks: Task[];
}

export interface TaskListResponse {
  tasks: Task[];
  total: number;
  limit: number;
  offset: number;
}

export interface RunWithTask extends Run {
  task_title: string;
  task_task_id: string;
  task_phase: string;
}

export interface RunListResponse {
  runs: RunWithTask[];
  total: number;
  limit: number;
  offset: number;
}

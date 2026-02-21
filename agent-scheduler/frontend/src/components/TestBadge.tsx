"use client";

interface TestBadgeProps {
  status: string | null;
}

export function TestBadge({ status }: TestBadgeProps) {
  if (!status) {
    return <span className="text-gray-600">-</span>;
  }

  const styles: Record<string, string> = {
    testing: "bg-blue-500/20 text-blue-400 animate-pulse",
    passed: "bg-green-500/20 text-green-400",
    failed: "bg-red-500/20 text-red-400",
  };

  const cls = styles[status] || "bg-gray-500/20 text-gray-400";

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status}
    </span>
  );
}

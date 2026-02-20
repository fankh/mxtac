"use client";

import { PhaseCard } from "@/components/PhaseCard";
import { useApi } from "@/hooks/useApi";
import { getPhases } from "@/lib/api";
import type { PhaseInfo } from "@/lib/types";

export default function PhasesPage() {
  const { data: phases, loading } = useApi<PhaseInfo[]>(() => getPhases(), []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">Phases</h1>
      {loading && <p className="text-gray-500">Loading...</p>}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {phases?.map((phase) => (
          <PhaseCard key={phase.phase} phase={phase} />
        ))}
      </div>
      {phases && phases.length === 0 && (
        <p className="text-gray-500">No phases found. Load tasks first.</p>
      )}
    </div>
  );
}

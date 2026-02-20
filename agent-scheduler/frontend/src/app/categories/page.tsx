"use client";

import { CategoryCard } from "@/components/CategoryCard";
import { useApi } from "@/hooks/useApi";
import { getCategories } from "@/lib/api";
import type { CategoryInfo } from "@/lib/types";

export default function CategoriesPage() {
  const { data: categories, loading } = useApi<CategoryInfo[]>(
    () => getCategories(),
    []
  );

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">Categories</h1>
      {loading && <p className="text-gray-500">Loading...</p>}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {categories?.map((cat) => (
          <CategoryCard key={cat.category} category={cat} />
        ))}
      </div>
      {categories && categories.length === 0 && (
        <p className="text-gray-500">No categories found. Load tasks first.</p>
      )}
    </div>
  );
}

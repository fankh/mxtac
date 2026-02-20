import type { Metadata } from "next";
import Link from "next/link";
import { AuthGuard } from "@/components/AuthGuard";
import { LogoutButton } from "@/components/LogoutButton";
import "./globals.css";

export const metadata: Metadata = {
  title: "Agent Scheduler",
  description: "AI Agent Task Scheduler for MxTac",
};

const navItems = [
  { href: "/", label: "Dashboard" },
  { href: "/history", label: "History" },
  { href: "/phases", label: "Phases" },
  { href: "/categories", label: "Categories" },
  { href: "/settings", label: "Settings" },
];

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-gray-950 text-gray-100 min-h-screen">
        <AuthGuard>
          <div className="flex">
            {/* Sidebar */}
            <aside className="w-56 min-h-screen bg-gray-900 border-r border-gray-800 p-4 shrink-0 flex flex-col">
              <h1 className="text-lg font-bold text-white mb-6">
                Agent Scheduler
              </h1>
              <nav className="space-y-1 flex-1">
                {navItems.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className="block px-3 py-2 rounded text-sm text-gray-300 hover:bg-gray-800 hover:text-white transition-colors"
                  >
                    {item.label}
                  </Link>
                ))}
              </nav>
              <LogoutButton />
            </aside>

            {/* Main content */}
            <main className="flex-1 p-6 overflow-auto">{children}</main>
          </div>
        </AuthGuard>
      </body>
    </html>
  );
}

import { lazy, Suspense } from 'react'
import { Navigate, Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/layout/Sidebar'
import { LoginPage } from './components/features/auth/LoginPage'
import { ProtectedRoute } from './components/shared/ProtectedRoute'
import { ErrorBoundary } from './components/shared/ErrorBoundary'
import { NotificationToast } from './components/shared/NotificationToast'
import { KeyboardShortcutsModal } from './components/shared/KeyboardShortcutsModal'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import { useUIStore } from './stores/uiStore'
import { Skeleton } from '@/components/ui/skeleton'

// Pages load on demand: the first paint ships only the shell and the page being opened.
const CoveragePage = lazy(() => import('./components/features/coverage/CoveragePage').then((m) => ({ default: m.CoveragePage })))
const HuntPage = lazy(() => import('./components/features/hunt/HuntPage').then((m) => ({ default: m.HuntPage })))
const SourcesPage = lazy(() => import('./components/features/sources/SourcesPage').then((m) => ({ default: m.SourcesPage })))
const SettingsPage = lazy(() => import('./components/features/settings/SettingsPage').then((m) => ({ default: m.SettingsPage })))
const OverviewPage = lazy(() => import('./components/features/overview/OverviewPage').then((m) => ({ default: m.OverviewPage })))
const DetectionsPage = lazy(() => import('./components/features/detections/DetectionsPage').then((m) => ({ default: m.DetectionsPage })))
const IncidentsPage = lazy(() => import('./components/features/incidents/IncidentsPage').then((m) => ({ default: m.IncidentsPage })))
const RulesPage = lazy(() => import('./components/features/rules/RulesPage').then((m) => ({ default: m.RulesPage })))

function PageFallback() {
  return (
    <div className="space-y-4 p-4" aria-busy="true" aria-label="Loading page">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-40 w-full rounded-lg" />
    </div>
  )
}

function MainLayout() {
  useKeyboardShortcuts()
  const showShortcutsModal = useUIStore(s => s.showShortcutsModal)

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      <Sidebar />
      <main className="min-w-0 flex-1 overflow-y-auto">
        <ErrorBoundary>
          <Suspense fallback={<PageFallback />}>
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/detections" element={<DetectionsPage />} />
            <Route path="/incidents" element={<IncidentsPage />} />
            <Route path="/hunt" element={<HuntPage />} />
            <Route path="/coverage" element={<CoveragePage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/sources" element={<SourcesPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          </Suspense>
        </ErrorBoundary>
      </main>
      <NotificationToast />
      {showShortcutsModal && <KeyboardShortcutsModal />}
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <MainLayout />
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}

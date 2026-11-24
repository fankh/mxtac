import { Check, Moon, Sun, type LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { useUIStore, type Theme } from '@/stores/uiStore'

const THEMES: { value: Theme; label: string; description: string; icon: LucideIcon }[] = [
  { value: 'light', label: 'Light', description: 'Bright background for well-lit rooms', icon: Sun },
  { value: 'dark', label: 'Dark', description: 'Dim background for low light', icon: Moon },
]

export function AppearanceTab() {
  const theme = useUIStore((s) => s.theme)
  const setTheme = useUIStore((s) => s.setTheme)

  return (
    <Card className="max-w-2xl">
      <CardContent className="space-y-3 p-4">
        <div>
          <h2 className="text-[12px] font-semibold text-foreground">Theme</h2>
          <p className="text-[11px] text-muted-foreground">Saved in this browser.</p>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {THEMES.map((t) => {
            const active = theme === t.value
            return (
              <Button
                key={t.value}
                variant="outline"
                aria-pressed={active}
                onClick={() => setTheme(t.value)}
                className={cn('h-auto justify-start gap-3 whitespace-normal p-3 text-left', active && 'border-primary bg-primary/10')}
              >
                <t.icon className="h-4 w-4 shrink-0" />
                <span className="flex-1">
                  <span className="block text-[12px] font-medium text-foreground">{t.label}</span>
                  <span className="block text-[11px] font-normal text-muted-foreground">{t.description}</span>
                </span>
                {active && <Check className="h-4 w-4 shrink-0 text-primary" />}
              </Button>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}

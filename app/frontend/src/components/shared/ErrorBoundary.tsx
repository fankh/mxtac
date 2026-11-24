import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback
      return (
        <div className="flex h-full min-h-[200px] flex-col items-center justify-center gap-3 p-6 max-md:pt-[58px]">
          <div className="text-[13px] font-semibold text-foreground">Something went wrong</div>
          <div className="max-w-md break-words text-center text-[11px] text-muted-foreground">
            {this.state.error?.message ?? 'An unexpected rendering error occurred.'}
          </div>
          <Button size="sm" onClick={() => this.setState({ hasError: false, error: null })}>
            Try again
          </Button>
        </div>
      )
    }
    return this.props.children
  }
}

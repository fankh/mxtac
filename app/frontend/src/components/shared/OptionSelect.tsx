import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { cn } from '@/lib/utils'

export interface SelectOption<T extends string> {
  value: T
  label: string
}

interface OptionSelectProps<T extends string> {
  /** Accessible name of the control. */
  label: string
  value: T
  options: SelectOption<T>[]
  onChange: (value: T) => void
  disabled?: boolean
  className?: string
}

/** A labelled single-choice dropdown over a fixed list of options. */
export function OptionSelect<T extends string>({
  label,
  value,
  options,
  onChange,
  disabled,
  className,
}: OptionSelectProps<T>) {
  function handleChange(next: string) {
    const match = options.find((option) => option.value === next)
    if (match) onChange(match.value)
  }

  return (
    <Select value={value} onValueChange={handleChange} disabled={disabled}>
      <SelectTrigger aria-label={label} className={cn('h-8 w-auto min-w-[120px] gap-2', className)}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

import * as React from "react"
import * as ProgressPrimitive from "@radix-ui/react-progress"

import { cn } from "@/lib/utils"

const Progress = React.forwardRef<
  React.ElementRef<typeof ProgressPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof ProgressPrimitive.Root> & { barColor?: string }
>(({ className, value, barColor = "rgba(100,108,255,1)", ...props }, ref) => {
  const safeValue = Math.max(0, Math.min(100, value != null ? value : 0))

  return (
    <ProgressPrimitive.Root
      ref={ref}
      className={cn(
        "relative h-3 w-full overflow-hidden rounded-lg bg-gray-400/50",
        className
      )}
      {...props}
    >
      <ProgressPrimitive.Indicator className="absolute left-0 top-0 h-full w-full">
        <svg
          className="h-full w-full transition-all duration-300"
          preserveAspectRatio="none"
          viewBox="0 0 100 100"
        >
          <rect
            x="0"
            y="0"
            width={safeValue}
            height="100"
            fill={barColor}
          />
        </svg>
      </ProgressPrimitive.Indicator>
    </ProgressPrimitive.Root>
  )
})

Progress.displayName = ProgressPrimitive.Root.displayName

export { Progress }

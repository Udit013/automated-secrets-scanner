/** Product mark: a keyhole cut from a solid square. Drawn, not imported. */
export function Mark({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" aria-hidden className="shrink-0">
      <rect x="1" y="1" width="18" height="18" rx="2" className="fill-ivory" />
      <circle cx="10" cy="8" r="2.6" className="fill-ink" />
      <path d="M8.9 9.5 L11.1 9.5 L12 15 L8 15 Z" className="fill-ink" />
    </svg>
  )
}

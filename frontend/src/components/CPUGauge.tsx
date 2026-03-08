interface CPUGaugeProps {
  /** Value 0–100, or -1 when not yet available */
  utilPct: number;
  /** Diameter of the SVG gauge in px (default 120) */
  size?: number;
}

/** Returns a colour that shifts from green → amber → red as utilisation rises */
function gaugeColor(pct: number): string {
  if (pct >= 85) return '#dc2626';
  if (pct >= 60) return '#ea580c';
  if (pct >= 40) return '#d97706';
  return '#16a34a';
}

/**
 * CPUGauge renders a semi-circular arc gauge showing CPU utilisation.
 * The arc sweeps 180° (left to right) so it fits compactly on the dashboard.
 */
export default function CPUGauge({ utilPct, size = 120 }: CPUGaugeProps) {
  const available  = utilPct >= 0;
  const pct        = available ? Math.min(100, Math.max(0, utilPct)) : 0;
  const cx         = size / 2;
  const cy         = size / 2 + 8;          // shift centre down a bit
  const r          = size * 0.38;
  const strokeW    = size * 0.09;
  const halfCirc   = Math.PI * r;           // circumference of a half circle
  const dashOffset = halfCirc * (1 - pct / 100);
  const color      = available ? gaugeColor(pct) : '#334155';

  // The arc starts at 9 o'clock (left) and sweeps to 3 o'clock (right).
  // We rotate −90° around the SVG origin then translate so the flat edge sits
  // at the bottom of the viewbox.  Achieved by setting a transform on the path.
  const arcPath = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg width={size} height={size * 0.6} viewBox={`0 0 ${size} ${size * 0.6}`} style={{ overflow: 'visible' }}>
        {/* Track */}
        <path
          d={arcPath}
          fill="none"
          stroke="#1e293b"
          strokeWidth={strokeW}
          strokeLinecap="round"
        />
        {/* Fill */}
        <path
          d={arcPath}
          fill="none"
          stroke={color}
          strokeWidth={strokeW}
          strokeLinecap="round"
          strokeDasharray={`${halfCirc}`}
          strokeDashoffset={dashOffset}
          style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.4s ease' }}
        />
        {/* Centre label */}
        <text
          x={cx}
          y={cy - strokeW * 0.1}
          textAnchor="middle"
          dominantBaseline="middle"
          fill={available ? '#f1f5f9' : '#475569'}
          fontSize={size * 0.2}
          fontWeight={700}
          fontFamily="inherit"
        >
          {available ? `${pct.toFixed(1)}%` : '—'}
        </text>
      </svg>
    </div>
  );
}

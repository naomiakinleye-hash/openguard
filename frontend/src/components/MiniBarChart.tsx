interface MiniBarChartProps {
  label: string;
  value: number;
  max: number;
  color: string;
}

export default function MiniBarChart({ label, value, max, color }: MiniBarChartProps) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;

  return (
    <div className="mini-bar-chart">
      <div className="mini-bar-label">
        <span>{label}</span>
        <span>{value}</span>
      </div>
      <div className="mini-bar-track">
        <div
          className="mini-bar-fill"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
    </div>
  );
}

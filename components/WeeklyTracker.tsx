export function WeeklyTracker({ studiedDays }: { studiedDays: boolean[] }) {
  const labels = ["M", "T", "W", "T", "F", "S", "S"];
  return (
    <div className="card">
      <h3 className="text-lg font-semibold">7-day Study Tracker</h3>
      <div className="mt-3 grid grid-cols-7 gap-2 text-center text-xs">
        {studiedDays.map((studied, i) => (
          <div key={i} className={`rounded-xl p-2 ${studied ? "bg-emerald-100 text-emerald-800" : "bg-slate-100 text-slate-500"}`}>
            <div>{labels[i]}</div>
            <div>{studied ? "✓" : "—"}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

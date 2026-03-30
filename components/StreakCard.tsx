export function StreakCard({ current, best, studiedToday, total }: { current: number; best: number; studiedToday: boolean; total: number }) {
  return (
    <div className="card">
      <h3 className="text-lg font-semibold">Study Streak</h3>
      <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
        <p>Current: <strong>{current}</strong></p>
        <p>Best: <strong>{best}</strong></p>
        <p>Studied today: <strong>{studiedToday ? "Yes" : "No"}</strong></p>
        <p>Total study days: <strong>{total}</strong></p>
      </div>
    </div>
  );
}

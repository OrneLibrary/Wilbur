export default function ProgressPage() {
  return (
    <main className="space-y-4">
      <h1 className="text-2xl font-bold">Progress</h1>
      <section className="grid gap-4 md:grid-cols-2">
        <div className="card"><h2 className="font-semibold">Quiz Scores by Subject</h2><p className="mt-2 text-sm">Math: 82%, Science: 76%, English: 79%, History: 73%, Religion: 88%, Spanish: 80%</p></div>
        <div className="card"><h2 className="font-semibold">Weak Topics</h2><p className="mt-2 text-sm">Ratios, Context clues, Government branches.</p></div>
        <div className="card"><h2 className="font-semibold">Streak Stats</h2><p className="mt-2 text-sm">Current streak: 3, Best streak: 4, Total study days: 18.</p></div>
        <div className="card"><h2 className="font-semibold">Subject Activity History</h2><p className="mt-2 text-sm">Shows study counts and last studied date per subject.</p></div>
      </section>
    </main>
  );
}

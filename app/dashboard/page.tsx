import Link from "next/link";
import { QuoteCard } from "@/components/QuoteCard";
import { StreakCard } from "@/components/StreakCard";
import { SubjectCard } from "@/components/SubjectCard";
import { WeeklyTracker } from "@/components/WeeklyTracker";
import { getDailyQuote } from "@/lib/constants/quotes";
import { seventhGradeSubjects } from "@/lib/constants/seed-content";

export default function DashboardPage() {
  const streak = { current: 3, best: 4, studiedToday: true, total: 18 };
  return (
    <main className="space-y-4">
      <section className="grid gap-4 md:grid-cols-2">
        <StreakCard {...streak} />
        <QuoteCard quote={getDailyQuote()} message="Great job studying 3 days in a row. Keep your streak alive today." />
      </section>

      <WeeklyTracker studiedDays={[true, true, false, true, true, false, true]} />

      <section className="card">
        <h2 className="text-xl font-semibold">Continue Studying</h2>
        <p className="text-sm text-slate-600">Recommended next action: Review "Solving Two-Step Equations" in Math.</p>
        <Link href="/lessons/les_math_2" className="mt-3 inline-block rounded-lg bg-calm-600 px-3 py-2 text-sm text-white">Continue</Link>
      </section>

      <section>
        <h2 className="mb-3 text-xl font-semibold">Subjects</h2>
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {seventhGradeSubjects.map((subject) => <SubjectCard key={subject.id} subject={subject} lastStudied="2026-03-29" />)}
        </div>
      </section>
    </main>
  );
}

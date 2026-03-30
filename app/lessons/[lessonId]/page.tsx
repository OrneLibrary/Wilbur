import { notFound } from "next/navigation";
import { AITutorPanel } from "@/components/AITutorPanel";
import { lessons } from "@/lib/constants/seed-content";

export default async function LessonPage({ params }: { params: Promise<{ lessonId: string }> }) {
  const { lessonId } = await params;
  const lesson = lessons.find((item) => item.id === lessonId);
  if (!lesson) notFound();

  return (
    <main className="space-y-4">
      <section className="card">
        <h1 className="text-2xl font-bold">{lesson.title}</h1>
        <p className="mt-2">{lesson.summary}</p>
      </section>
      <section className="grid gap-4 md:grid-cols-3">
        <div className="card"><h2 className="font-semibold">Key Terms</h2><ul className="mt-2 list-disc pl-5 text-sm">{lesson.keyTerms.map((term) => <li key={term}>{term}</li>)}</ul></div>
        <div className="card"><h2 className="font-semibold">Examples</h2><ul className="mt-2 list-disc pl-5 text-sm">{lesson.examples.map((item) => <li key={item}>{item}</li>)}</ul></div>
        <div className="card"><h2 className="font-semibold">Practice Questions</h2><ul className="mt-2 list-disc pl-5 text-sm">{lesson.practiceQuestions.map((item) => <li key={item}>{item}</li>)}</ul></div>
      </section>
      <AITutorPanel subjectSlug={lesson.subjectSlug} lessonId={lesson.id} />
    </main>
  );
}

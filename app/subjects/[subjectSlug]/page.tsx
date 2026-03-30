import { notFound } from "next/navigation";
import { AITutorPanel } from "@/components/AITutorPanel";
import { FileUploadArea } from "@/components/FileUploadArea";
import { FlashcardViewer } from "@/components/FlashcardViewer";
import { QuizCard } from "@/components/QuizCard";
import { flashcards, lessons, quizzes, seventhGradeSubjects } from "@/lib/constants/seed-content";

export default async function SubjectPage({ params }: { params: Promise<{ subjectSlug: string }> }) {
  const { subjectSlug } = await params;
  const subject = seventhGradeSubjects.find((s) => s.slug === subjectSlug);
  if (!subject) notFound();
  const subjectLessons = lessons.filter((lesson) => lesson.subjectSlug === subjectSlug);
  const lessonIds = new Set(subjectLessons.map((l) => l.id));

  return (
    <main className="space-y-4">
      <section className="card">
        <h1 className="text-2xl font-bold">{subject.name}</h1>
        <p className="text-sm text-slate-600">{subject.description}</p>
        <p className="mt-2 text-xs text-slate-500">Last studied: 2026-03-29 | Subject progress: 62%</p>
      </section>

      <section className="card">
        <h2 className="text-lg font-semibold">Units & Lessons</h2>
        <ul className="mt-2 space-y-2 text-sm">
          {subjectLessons.map((lesson) => (
            <li key={lesson.id} className="rounded-lg border p-2">
              <p className="font-medium">{lesson.unitTitle}: {lesson.title}</p>
              <p className="text-slate-600">{lesson.summary}</p>
            </li>
          ))}
        </ul>
      </section>

      <FileUploadArea subjectId={subject.id} />
      <FlashcardViewer cards={flashcards.filter((f) => f.lessonId && lessonIds.has(f.lessonId))} />
      <QuizCard questions={quizzes.filter((q) => q.lessonId && lessonIds.has(q.lessonId))} />
      <AITutorPanel subjectSlug={subjectSlug} />
    </main>
  );
}

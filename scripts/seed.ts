import { createClient } from "@supabase/supabase-js";
import { flashcards, lessons, quizzes, seventhGradeSubjects } from "../lib/constants/seed-content";

async function main() {
  const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

  await supabase.from("grades").upsert([{ id: "grade_7", name: "7th Grade", sort_order: 7 }]);
  await supabase.from("subjects").upsert(seventhGradeSubjects.map((s) => ({ id: s.id, grade_id: s.gradeId, name: s.name, slug: s.slug, description: s.description })));
  await supabase.from("lessons").upsert(lessons.map((l) => ({ id: l.id, title: l.title, summary: l.summary, content_json: { keyTerms: l.keyTerms, examples: l.examples, practiceQuestions: l.practiceQuestions } })));
  await supabase.from("flashcards").upsert(flashcards.map((f) => ({ id: f.id, lesson_id: f.lessonId ?? null, front_text: f.frontText, back_text: f.backText })));
  await supabase.from("quizzes").upsert(quizzes.map((q) => ({ id: q.id, lesson_id: q.lessonId ?? null, question_text: q.questionText, choices_json: q.choices, correct_answer: q.correctAnswer, explanation: q.explanation })));

  console.log("Seed complete");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

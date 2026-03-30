import { lessons } from "@/lib/constants/seed-content";

export async function searchSubjectSources(subjectSlug: string, question: string) {
  // Retrieval priority: uploaded files -> built-in lesson content -> general fallback.
  // For production, replace placeholder with pgvector + Supabase query.
  const lessonMatch = lessons.find((lesson) => lesson.subjectSlug === subjectSlug && `${lesson.summary} ${lesson.keyTerms.join(" ")}`.toLowerCase().includes(question.toLowerCase()));
  if (lessonMatch) {
    return {
      sourceType: "lesson",
      sourceLabel: lessonMatch.title,
      context: `${lessonMatch.summary}\nKey terms: ${lessonMatch.keyTerms.join(", ")}`
    };
  }

  return { sourceType: "general", sourceLabel: "General tutoring knowledge", context: "" };
}

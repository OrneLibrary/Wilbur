export type Grade = { id: string; name: string; sortOrder: number };
export type Subject = { id: string; gradeId: string; name: string; slug: string; description: string };
export type Lesson = {
  id: string;
  subjectSlug: string;
  unitTitle: string;
  title: string;
  summary: string;
  keyTerms: string[];
  examples: string[];
  practiceQuestions: string[];
};

export type Flashcard = { id: string; lessonId?: string; frontText: string; backText: string };
export type QuizQuestion = {
  id: string;
  lessonId?: string;
  questionText: string;
  choices: string[];
  correctAnswer: string;
  explanation: string;
};

export type UploadedFile = {
  id: string;
  studentId: string;
  gradeId: string;
  subjectId: string;
  unitId?: string;
  fileName: string;
  fileType: string;
  createdAt: string;
};

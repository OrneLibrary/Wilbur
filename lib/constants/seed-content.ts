import { Flashcard, Lesson, QuizQuestion, Subject } from "@/types/domain";

export const seventhGradeSubjects: Subject[] = [
  { id: "sub_math_7", gradeId: "grade_7", name: "Math", slug: "math", description: "Ratios, expressions, and geometry foundations." },
  { id: "sub_science_7", gradeId: "grade_7", name: "Science", slug: "science", description: "Life science, chemistry basics, and scientific method." },
  { id: "sub_reading_7", gradeId: "grade_7", name: "Reading/English", slug: "reading-english", description: "Vocabulary, grammar, and reading comprehension." },
  { id: "sub_history_7", gradeId: "grade_7", name: "History/Social Studies", slug: "history-social-studies", description: "Civilizations, government, and historical thinking." },
  { id: "sub_religion_7", gradeId: "grade_7", name: "Religion", slug: "religion", description: "Faith concepts, character, and reflection." },
  { id: "sub_spanish_7", gradeId: "grade_7", name: "Spanish", slug: "spanish", description: "Vocabulary, grammar, and speaking practice." }
];

export const lessons: Lesson[] = [
  { id: "les_math_1", subjectSlug: "math", unitTitle: "Ratios and Proportions", title: "Proportional Relationships", summary: "Learn to compare ratios and identify proportional situations from tables and graphs.", keyTerms: ["ratio", "proportion", "unit rate"], examples: ["3 notebooks for $6 means $2 per notebook.", "If 4 apples cost $8, 1 apple costs $2."], practiceQuestions: ["Is 2/5 equal to 6/15?", "Find the unit rate for 18 miles in 3 hours."] },
  { id: "les_math_2", subjectSlug: "math", unitTitle: "Expressions", title: "Solving Two-Step Equations", summary: "Use inverse operations to solve equations with two steps.", keyTerms: ["variable", "inverse operation", "equation"], examples: ["x + 5 = 17", "3x - 4 = 11"], practiceQuestions: ["Solve: 2x + 9 = 25", "Solve: 5x - 10 = 20"] },
  { id: "les_science_1", subjectSlug: "science", unitTitle: "Cell Biology", title: "Cell Structure and Function", summary: "Explore key organelles and their jobs inside plant and animal cells.", keyTerms: ["nucleus", "mitochondria", "cell membrane"], examples: ["The nucleus stores DNA.", "Mitochondria release energy."], practiceQuestions: ["What does the cell membrane do?", "How are plant and animal cells different?"] },
  { id: "les_science_2", subjectSlug: "science", unitTitle: "Scientific Inquiry", title: "Variables in Experiments", summary: "Identify independent, dependent, and controlled variables.", keyTerms: ["independent variable", "dependent variable", "control"], examples: ["Changing light amount for plant growth test."], practiceQuestions: ["Name the dependent variable in a sleep study."] },
  { id: "les_read_1", subjectSlug: "reading-english", unitTitle: "Vocabulary", title: "Context Clues", summary: "Use nearby words to infer the meaning of unknown vocabulary.", keyTerms: ["context clues", "inference", "synonym"], examples: ["The arid desert was dry and hot."], practiceQuestions: ["What does arid mean from the sentence?"] },
  { id: "les_read_2", subjectSlug: "reading-english", unitTitle: "Grammar", title: "Sentence Structure", summary: "Identify simple, compound, and complex sentences.", keyTerms: ["clause", "conjunction", "independent clause"], examples: ["I studied, and I felt confident."], practiceQuestions: ["Label this sentence type: Because it rained, we stayed in."] },
  { id: "les_hist_1", subjectSlug: "history-social-studies", unitTitle: "World History", title: "Ancient Civilizations", summary: "Compare how geography shaped early civilizations.", keyTerms: ["civilization", "irrigation", "trade"], examples: ["Rivers helped farming in Mesopotamia."], practiceQuestions: ["Why were rivers important to early cities?"] },
  { id: "les_hist_2", subjectSlug: "history-social-studies", unitTitle: "Civics", title: "Branches of Government", summary: "Understand powers of legislative, executive, and judicial branches.", keyTerms: ["legislative", "executive", "judicial"], examples: ["Congress makes laws."], practiceQuestions: ["Which branch interprets laws?"] },
  { id: "les_rel_1", subjectSlug: "religion", unitTitle: "Character", title: "Virtues in Daily Life", summary: "Practice kindness, patience, and honesty in school and home life.", keyTerms: ["virtue", "integrity", "compassion"], examples: ["Helping a classmate without being asked."], practiceQuestions: ["Give one example of integrity."] },
  { id: "les_rel_2", subjectSlug: "religion", unitTitle: "Scripture", title: "Parables and Meaning", summary: "Interpret key messages in short scripture stories.", keyTerms: ["parable", "moral", "reflection"], examples: ["A parable teaches a lesson through story."], practiceQuestions: ["What lesson can a parable teach?"] },
  { id: "les_span_1", subjectSlug: "spanish", unitTitle: "Basics", title: "Greetings and Introductions", summary: "Use common greetings and basic introduction phrases.", keyTerms: ["hola", "buenos días", "me llamo"], examples: ["Hola, me llamo Ana."], practiceQuestions: ["How do you say 'My name is...'? "] },
  { id: "les_span_2", subjectSlug: "spanish", unitTitle: "Grammar", title: "Present Tense of Ser", summary: "Conjugate ser to describe identity and origin.", keyTerms: ["soy", "eres", "es"], examples: ["Yo soy estudiante."], practiceQuestions: ["Translate: We are friends."] }
];

export const flashcards: Flashcard[] = lessons.flatMap((lesson, idx) => [
  { id: `fc_${idx}_1`, lessonId: lesson.id, frontText: `${lesson.title}: key term`, backText: lesson.keyTerms[0] ?? "term" },
  { id: `fc_${idx}_2`, lessonId: lesson.id, frontText: `${lesson.title}: summary`, backText: lesson.summary }
]);

export const quizzes: QuizQuestion[] = lessons.map((lesson, idx) => ({
  id: `q_${idx}_1`,
  lessonId: lesson.id,
  questionText: `Quick check: ${lesson.practiceQuestions[0]}`,
  choices: ["Option A", "Option B", "Option C", "Option D"],
  correctAnswer: "Option A",
  explanation: `Review ${lesson.keyTerms[0]} in ${lesson.title}.`
}));

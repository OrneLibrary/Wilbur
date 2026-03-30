# Study Buddy (Next.js + Supabase + OpenAI)

Study Buddy is a production-ready, website-first learning platform designed for a 7th-grade student today, with grade-aware architecture that supports progression into future grades without rebuilding.

## Tech Stack
- Next.js (App Router)
- TypeScript
- Tailwind CSS
- Supabase (Auth, Postgres, Storage)
- OpenAI API (tutor, summarization, quiz/flashcard generation)

## Features Implemented
- Mobile-first dashboard with streaks, daily motivation, weekly tracker, recent/recommended study actions.
- Grade-aware content model (grades, subjects, units, lessons, uploads, quizzes, flashcards, progress).
- Seeded 7th-grade subjects: Math, Science, Reading/English, History/Social Studies, Religion, Spanish.
- Subject pages: units/lessons, file upload section, flashcards, quizzes, AI tutor.
- Lesson pages: summary, key terms, examples, practice questions, lesson-specific tutor.
- Progress + review mistakes pages.
- Parent/admin placeholder page.
- Supabase migration schema + seed script.
- API routes for tutor chat, upload, retrieval search, flashcard/quiz generation, session logging, streaks, quote, and file actions.

## Project Structure
- `app/` — pages and API routes
- `components/` — reusable UI blocks
- `lib/` — OpenAI/Supabase clients, retrieval and streak services, constants
- `supabase/migrations/` — SQL schema
- `scripts/seed.ts` — seed script for grade 7 sample data
- `types/` — domain types

## Setup
1. Install dependencies:
   ```bash
   npm install
   ```
2. Copy envs:
   ```bash
   cp .env.example .env.local
   ```
3. Fill in Supabase and OpenAI keys.
4. Run Supabase migration SQL in your Supabase project.
5. Run seed script:
   ```bash
   npm run seed
   ```
6. Start development server:
   ```bash
   npm run dev
   ```

## Local Development Notes
- App runs at `http://localhost:3000`.
- Upload bucket expected: `study-materials`.
- Retrieval flow priority:
  1) Uploaded subject materials
  2) Built-in lesson content
  3) General tutoring fallback

## Deployment Guidance
- Deploy on Vercel or any Node-compatible platform.
- Configure environment variables from `.env.example`.
- Ensure Supabase URL/keys are set and DB schema is migrated.
- Lock down service-role use to server-side code only.

## Authentication (Scaffold)
- Supabase auth integration scaffold included.
- Roles targeted for V1: `student`, `parent_admin`.

## Future Expansion (Already Structured)
- Multi-grade rollout by inserting new grades + grade-linked subjects/units/lessons.
- Achievement/badge system can be added from study sessions + progress tables.
- Replace retrieval placeholder with pgvector and embeddings search pipeline.

create extension if not exists "pgcrypto";

create table if not exists grades (
  id text primary key,
  name text not null,
  sort_order int not null
);

create table if not exists students (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid unique,
  name text not null,
  role text not null default 'student' check (role in ('student','parent_admin')),
  current_grade_id text references grades(id),
  created_at timestamptz not null default now()
);

create table if not exists subjects (
  id text primary key,
  grade_id text not null references grades(id) on delete cascade,
  name text not null,
  slug text not null unique,
  description text,
  created_at timestamptz not null default now()
);

create table if not exists units (
  id uuid primary key default gen_random_uuid(),
  subject_id text not null references subjects(id) on delete cascade,
  title text not null,
  sort_order int not null default 1
);

create table if not exists lessons (
  id text primary key,
  unit_id uuid references units(id) on delete set null,
  title text not null,
  summary text not null,
  content_json jsonb,
  sort_order int not null default 1,
  created_at timestamptz not null default now()
);

create table if not exists uploaded_files (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  grade_id text not null references grades(id),
  subject_id text not null references subjects(id),
  unit_id uuid references units(id),
  file_name text not null,
  file_type text not null,
  storage_path text not null,
  openai_file_id text,
  vector_store_id text,
  created_at timestamptz not null default now()
);

create table if not exists flashcards (
  id text primary key,
  lesson_id text references lessons(id) on delete set null,
  uploaded_file_id uuid references uploaded_files(id) on delete cascade,
  front_text text not null,
  back_text text not null,
  created_at timestamptz not null default now()
);

create table if not exists quizzes (
  id text primary key,
  lesson_id text references lessons(id) on delete set null,
  uploaded_file_id uuid references uploaded_files(id) on delete cascade,
  question_text text not null,
  choices_json jsonb not null,
  correct_answer text not null,
  explanation text not null,
  created_at timestamptz not null default now()
);

create table if not exists quiz_attempts (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  quiz_id text not null references quizzes(id) on delete cascade,
  selected_answer text not null,
  is_correct boolean not null,
  created_at timestamptz not null default now()
);

create table if not exists study_sessions (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  grade_id text not null references grades(id),
  subject_id text not null references subjects(id),
  lesson_id text references lessons(id) on delete set null,
  uploaded_file_id uuid references uploaded_files(id) on delete set null,
  action_type text not null,
  duration_minutes int,
  created_at timestamptz not null default now()
);

create table if not exists student_progress (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  subject_id text not null references subjects(id) on delete cascade,
  current_streak int not null default 0,
  best_streak int not null default 0,
  total_study_days int not null default 0,
  last_studied_at timestamptz,
  updated_at timestamptz not null default now(),
  unique(student_id, subject_id)
);

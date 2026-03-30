import { NextResponse } from "next/server";
import { createSupabaseServerClient } from "@/lib/supabase/client";

const ACCEPTED = ["application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "text/plain", "image/png", "image/jpeg"];

export async function POST(req: Request) {
  const form = await req.formData();
  const file = form.get("file") as File | null;
  const subjectId = String(form.get("subjectId") ?? "");
  if (!file || !subjectId) return NextResponse.json({ error: "Missing file or subject" }, { status: 400 });
  if (!ACCEPTED.includes(file.type)) return NextResponse.json({ error: "Unsupported file type" }, { status: 400 });

  const supabase = createSupabaseServerClient();
  const storagePath = `uploads/${Date.now()}-${file.name}`;
  await supabase.storage.from("study-materials").upload(storagePath, file);
  await supabase.from("uploaded_files").insert({
    student_id: "00000000-0000-0000-0000-000000000001",
    grade_id: "grade_7",
    subject_id: subjectId,
    file_name: file.name,
    file_type: file.type,
    storage_path: storagePath
  });

  return NextResponse.redirect(new URL(req.headers.get("referer") ?? "/dashboard"));
}

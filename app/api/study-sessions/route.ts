import { NextResponse } from "next/server";
import { createSupabaseServerClient } from "@/lib/supabase/client";

export async function POST(req: Request) {
  const payload = await req.json();
  const supabase = createSupabaseServerClient();
  const { error } = await supabase.from("study_sessions").insert(payload);
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json({ ok: true });
}

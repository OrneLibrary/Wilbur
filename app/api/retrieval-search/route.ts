import { NextResponse } from "next/server";
import { searchSubjectSources } from "@/lib/services/retrieval";

export async function POST(req: Request) {
  const { subjectSlug, query } = await req.json();
  const result = await searchSubjectSources(subjectSlug, query);
  return NextResponse.json(result);
}

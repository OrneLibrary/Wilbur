import { NextResponse } from "next/server";
import { createOpenAIClient, tutorSystemPrompt } from "@/lib/openai/client";
import { searchSubjectSources } from "@/lib/services/retrieval";

export async function POST(req: Request) {
  const { subjectSlug, message } = await req.json();
  if (!subjectSlug || !message) return NextResponse.json({ error: "Missing fields" }, { status: 400 });

  const retrieval = await searchSubjectSources(subjectSlug, message);
  const client = createOpenAIClient();
  const completion = await client.responses.create({
    model: "gpt-4.1-mini",
    input: [
      { role: "system", content: tutorSystemPrompt },
      { role: "user", content: `Subject: ${subjectSlug}\nSource type: ${retrieval.sourceType}\nContext: ${retrieval.context}\nQuestion: ${message}` }
    ]
  });

  return NextResponse.json({
    answer: completion.output_text,
    source: retrieval.sourceLabel
  });
}

import { NextResponse } from "next/server";
import { createOpenAIClient } from "@/lib/openai/client";

export async function POST(req: Request) {
  const { text } = await req.json();
  const client = createOpenAIClient();
  const result = await client.responses.create({
    model: "gpt-4.1-mini",
    input: `Create 5 study flashcards from this text in JSON array format with frontText/backText: ${text}`
  });
  return NextResponse.json({ raw: result.output_text });
}

import { NextResponse } from "next/server";
import { createOpenAIClient } from "@/lib/openai/client";

export async function POST(req: Request) {
  const { text } = await req.json();
  const client = createOpenAIClient();
  const result = await client.responses.create({
    model: "gpt-4.1-mini",
    input: `Create 5 multiple choice quiz questions from this text in JSON with question, choices, correctAnswer, explanation: ${text}`
  });
  return NextResponse.json({ raw: result.output_text });
}

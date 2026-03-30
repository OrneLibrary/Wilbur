import { NextResponse } from "next/server";
import { createOpenAIClient } from "@/lib/openai/client";

export async function POST(req: Request) {
  const { action, text } = await req.json();
  const client = createOpenAIClient();
  const result = await client.responses.create({
    model: "gpt-4.1-mini",
    input: `${action}: ${text}`
  });
  return NextResponse.json({ output: result.output_text });
}

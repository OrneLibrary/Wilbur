import { NextResponse } from "next/server";
import { getDailyQuote } from "@/lib/constants/quotes";

export async function GET() {
  return NextResponse.json({ quote: getDailyQuote() });
}

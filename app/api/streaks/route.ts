import { NextResponse } from "next/server";
import { calculateStreak } from "@/lib/services/streaks";

export async function POST(req: Request) {
  const { studiedDays } = await req.json();
  return NextResponse.json(calculateStreak(studiedDays ?? []));
}

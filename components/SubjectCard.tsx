import Link from "next/link";
import { Subject } from "@/types/domain";

export function SubjectCard({ subject, lastStudied }: { subject: Subject; lastStudied?: string }) {
  return (
    <Link href={`/subjects/${subject.slug}`} className="card block hover:ring-calm-600">
      <h3 className="text-lg font-semibold">{subject.name}</h3>
      <p className="mt-1 text-sm text-slate-600">{subject.description}</p>
      <p className="mt-3 text-xs text-slate-500">Last studied: {lastStudied ?? "Not yet"}</p>
    </Link>
  );
}

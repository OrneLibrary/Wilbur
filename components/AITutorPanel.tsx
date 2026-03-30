"use client";
import { useState } from "react";

const quickActions = ["Explain simpler", "Give an example", "Quiz me", "Summarize this file", "Translate this"];

export function AITutorPanel({ subjectSlug, lessonId }: { subjectSlug: string; lessonId?: string }) {
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");

  async function ask(prompt: string) {
    const res = await fetch("/api/tutor", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subjectSlug, lessonId, message: prompt })
    });
    const data = await res.json();
    setAnswer(`${data.answer}\n\nSource: ${data.source}`);
  }

  return (
    <div className="card">
      <h3 className="text-lg font-semibold">AI Tutor</h3>
      <div className="mt-2 flex flex-wrap gap-2">
        {quickActions.map((action) => (
          <button key={action} className="rounded-full bg-slate-100 px-3 py-1 text-xs" onClick={() => ask(`${action}: ${question}`)}>{action}</button>
        ))}
      </div>
      <textarea className="mt-3 w-full rounded-xl border p-2 text-sm" rows={4} value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask for help..." />
      <button className="mt-2 rounded-lg bg-calm-600 px-3 py-2 text-white" onClick={() => ask(question)}>Ask Tutor</button>
      {answer && <pre className="mt-3 whitespace-pre-wrap rounded-xl bg-slate-100 p-3 text-sm">{answer}</pre>}
    </div>
  );
}

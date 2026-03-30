"use client";
import { useState } from "react";
import { QuizQuestion } from "@/types/domain";

export function QuizCard({ questions }: { questions: QuizQuestion[] }) {
  const [index, setIndex] = useState(0);
  const [score, setScore] = useState(0);
  const [feedback, setFeedback] = useState<string>("");
  const question = questions[index];
  if (!question) return <div className="card">No quiz questions yet.</div>;

  return (
    <div className="card">
      <h3 className="text-lg font-semibold">Quiz Mode</h3>
      <p className="mt-2 text-sm">{question.questionText}</p>
      <div className="mt-3 space-y-2">
        {question.choices.map((choice) => (
          <button
            key={choice}
            onClick={() => {
              const correct = choice === question.correctAnswer;
              setFeedback(`${correct ? "Correct" : "Not quite"}. ${question.explanation}`);
              if (correct) setScore((s) => s + 1);
            }}
            className="w-full rounded-lg border p-2 text-left"
          >
            {choice}
          </button>
        ))}
      </div>
      {feedback && <p className="mt-3 text-sm">{feedback}</p>}
      <div className="mt-3 flex items-center justify-between text-sm">
        <span>Score: {score}</span>
        <button className="rounded-lg bg-calm-600 px-3 py-1 text-white" onClick={() => { setIndex((i) => Math.min(questions.length - 1, i + 1)); setFeedback(""); }}>Next Question</button>
      </div>
    </div>
  );
}

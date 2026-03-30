"use client";
import { useState } from "react";
import { Flashcard } from "@/types/domain";

export function FlashcardViewer({ cards }: { cards: Flashcard[] }) {
  const [index, setIndex] = useState(0);
  const [flipped, setFlipped] = useState(false);
  const card = cards[index];
  if (!card) return <div className="card">No flashcards yet.</div>;
  return (
    <div className="card">
      <h3 className="text-lg font-semibold">Flashcards ({index + 1}/{cards.length})</h3>
      <button className="mt-3 w-full rounded-xl bg-slate-100 p-6 text-left" onClick={() => setFlipped((f) => !f)}>
        {flipped ? card.backText : card.frontText}
      </button>
      <div className="mt-3 flex gap-2">
        <button className="rounded-lg bg-slate-200 px-3 py-1" onClick={() => { setIndex((i) => Math.max(0, i - 1)); setFlipped(false); }}>Previous</button>
        <button className="rounded-lg bg-slate-200 px-3 py-1" onClick={() => { setIndex((i) => Math.min(cards.length - 1, i + 1)); setFlipped(false); }}>Next</button>
      </div>
    </div>
  );
}

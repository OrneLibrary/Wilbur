export function calculateStreak(days: string[]) {
  const sorted = [...new Set(days)].sort().reverse();
  let current = 0;
  let cursor = new Date();
  while (sorted.includes(cursor.toISOString().slice(0, 10))) {
    current += 1;
    cursor.setUTCDate(cursor.getUTCDate() - 1);
  }
  return { current, best: Math.max(current, 1), studiedToday: sorted.includes(new Date().toISOString().slice(0, 10)) };
}

export const motivationalQuotes = [
  "Small progress is still progress.",
  "Consistency beats cramming.",
  "One study session today makes tomorrow easier.",
  "You are getting stronger every time you practice."
];

export function getDailyQuote(date = new Date()) {
  const day = Number(date.toISOString().slice(0, 10).replaceAll("-", ""));
  return motivationalQuotes[day % motivationalQuotes.length];
}

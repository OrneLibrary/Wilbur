export function QuoteCard({ quote, message }: { quote: string; message: string }) {
  return (
    <div className="card bg-calm-50">
      <h3 className="text-lg font-semibold text-calm-600">Daily Motivation</h3>
      <p className="mt-2 text-sm">“{quote}”</p>
      <p className="mt-2 text-sm text-slate-600">{message}</p>
    </div>
  );
}

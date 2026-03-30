import "./globals.css";
import Link from "next/link";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="mx-auto min-h-screen max-w-6xl px-4 py-4 md:px-8">
          <header className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-2xl bg-white p-4 shadow-sm ring-1 ring-slate-200">
            <Link href="/dashboard" className="text-xl font-bold text-calm-600">Study Buddy</Link>
            <nav className="flex gap-3 text-sm font-medium text-slate-600">
              <Link href="/dashboard">Dashboard</Link>
              <Link href="/progress">Progress</Link>
              <Link href="/review-mistakes">Review Mistakes</Link>
              <Link href="/admin">Parent/Admin</Link>
            </nav>
          </header>
          {children}
        </div>
      </body>
    </html>
  );
}

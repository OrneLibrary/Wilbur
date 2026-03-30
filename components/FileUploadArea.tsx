"use client";

export function FileUploadArea({ subjectId }: { subjectId: string }) {
  return (
    <form action="/api/upload" method="post" encType="multipart/form-data" className="card space-y-2">
      <h3 className="text-lg font-semibold">Upload Study Material</h3>
      <p className="text-xs text-amber-700">Upload only class materials you are allowed to use (no full copyrighted textbooks).</p>
      <input type="hidden" name="subjectId" value={subjectId} />
      <input name="file" type="file" accept=".pdf,.docx,.txt,.png,.jpg,.jpeg" className="w-full text-sm" />
      <button className="rounded-lg bg-calm-600 px-3 py-2 text-white" type="submit">Upload</button>
    </form>
  );
}

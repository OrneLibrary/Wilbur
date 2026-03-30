import { createSupabaseServerClient } from "@/lib/supabase/client";

export async function getCurrentUser() {
  const supabase = createSupabaseServerClient();
  const { data } = await supabase.auth.getUser();
  return data.user;
}

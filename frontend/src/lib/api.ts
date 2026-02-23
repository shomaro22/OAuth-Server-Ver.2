const base =
  (import.meta.env.VITE_API_BASE as string) || "http://localhost:8080";

export const apiBase = base;

export type ApiError = { status: number; message: string };

export async function apiFetch<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const res = await fetch(`${base}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw {
      status: res.status,
      message: text || res.statusText,
    } satisfies ApiError;
  }

  return (await res.json()) as T;
}

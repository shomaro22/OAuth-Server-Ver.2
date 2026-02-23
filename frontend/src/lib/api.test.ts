import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiFetch } from "./api";

describe("apiFetch", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn() as typeof fetch);
  });

  it("成功時は JSON を返す", async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ next_url: "http://example.com/consent" }),
      text: () => Promise.resolve(""),
    } as Response);

    const result = await apiFetch<{ next_url: string }>("/sessions/login", {
      method: "POST",
      body: JSON.stringify({ login_challenge: "x", username: "u", password: "p" }),
    });

    expect(result).toEqual({ next_url: "http://example.com/consent" });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/sessions/login"),
      expect.objectContaining({ method: "POST", credentials: "include" })
    );
  });

  it("失敗時は ApiError を throw", async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      text: () => Promise.resolve("invalid credentials"),
    } as Response);

    await expect(apiFetch("/sessions/login")).rejects.toMatchObject({
      status: 401,
      message: "invalid credentials",
    });
  });
});

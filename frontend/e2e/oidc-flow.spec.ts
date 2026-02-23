import { test, expect } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";

const API_BASE = process.env.VITE_API_BASE ?? "http://localhost:8080";
const CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CLIENT_ID = "11111111-1111-1111-1111-111111111111";
const REDIRECT_URI = "http://localhost:5173/callback";

test.describe("OIDC flow", () => {
  test("authorize → login → consent → callback で code 取得", async ({
    page,
  }) => {
    test.setTimeout(60000);

    const state = "e2e-" + Date.now();
    const codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    const authUrl = new URL(`${API_BASE}/oauth/authorize`);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
    authUrl.searchParams.set("scope", "openid");
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");
    authUrl.searchParams.set("nonce", "e2e-nonce");

    await page.goto(authUrl.toString(), { waitUntil: "networkidle" });

    await expect(page).toHaveURL(/\/login/, { timeout: 15000 });
    await expect(page.getByRole("heading", { name: "Login" })).toBeVisible();
    await expect(page.getByTestId("username")).toBeVisible({ timeout: 10000 });
    await page.getByTestId("username").fill("testuser");
    await page.getByTestId("password").fill("password123");
    await page.getByTestId("login-submit").click();

    await page.waitForURL(/\/consent|\/callback/, { timeout: 15000 });
    if (page.url().includes("/consent")) {
      await expect(page.getByRole("heading", { name: "アプリの許可" })).toBeVisible();
      await expect(page.getByTestId("consent-approve")).toBeVisible({ timeout: 5000 });
      await page.getByTestId("consent-approve").click();
      await page.waitForURL(/\/callback/, { timeout: 15000 });
    }

    await expect(page).toHaveURL(/\/callback/);
    await expect(page.getByText(/認可成功/)).toBeVisible();
    const url = new URL(page.url());
    const code = url.searchParams.get("code");
    expect(code).toBeTruthy();
    expect(url.searchParams.get("state")).toBe(state);

    // token 交換して id_token を取得し、証跡用に保存
    const tokenRes = await page.evaluate(
      async ({ apiBase, code, redirectUri, clientId, verifier }) => {
        const body = new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          client_id: clientId,
          code_verifier: verifier,
        });
        const res = await fetch(`${apiBase}/oauth/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: body.toString(),
        });
        return res.ok ? await res.json() : null;
      },
      {
        apiBase: API_BASE,
        code: code!,
        redirectUri: REDIRECT_URI,
        clientId: CLIENT_ID,
        verifier: CODE_VERIFIER,
      }
    );
    if (tokenRes?.id_token) {
      const outDir = path.join(process.cwd(), "..", "backend", "tests", "evidence", "config");
      fs.mkdirSync(outDir, { recursive: true });
      fs.writeFileSync(path.join(outDir, "e2e_id_token.txt"), tokenRes.id_token, "utf8");
    }
  });
});

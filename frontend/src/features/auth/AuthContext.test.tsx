import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthProvider, useAuth } from "./AuthContext";

function TestConsumer() {
  const { isAuthenticated, setAuthenticated } = useAuth();
  return (
    <div>
      <span data-testid="auth-state">{isAuthenticated ? "logged-in" : "logged-out"}</span>
      <button onClick={() => setAuthenticated(true)}>Login</button>
      <button onClick={() => setAuthenticated(false)}>Logout</button>
    </div>
  );
}

describe("AuthContext", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it("初期状態は logged-out", () => {
    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    );
    expect(screen.getByTestId("auth-state")).toHaveTextContent("logged-out");
  });

  it("Login で logged-in に変わる", async () => {
    const user = userEvent.setup();
    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    );
    await user.click(screen.getByText("Login"));
    expect(screen.getByTestId("auth-state")).toHaveTextContent("logged-in");
  });

  it("Logout で logged-out に戻る", async () => {
    const user = userEvent.setup();
    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    );
    await user.click(screen.getByText("Login"));
    await user.click(screen.getByText("Logout"));
    expect(screen.getByTestId("auth-state")).toHaveTextContent("logged-out");
  });
});

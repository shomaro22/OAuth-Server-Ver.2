import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import Callback from "./Callback";

function renderWithRouter(initialEntries: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntries]}>
      <Routes>
        <Route path="/callback" element={<Callback />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("Callback", () => {
  it("code と state があるとき成功表示", () => {
    renderWithRouter("/callback?code=abc123&state=xyz");
    expect(screen.getByText(/認可成功/)).toBeInTheDocument();
    expect(screen.getByText("abc123")).toBeInTheDocument();
    expect(screen.getByText("xyz")).toBeInTheDocument();
  });

  it("code がないとき案内表示", () => {
    renderWithRouter("/callback");
    expect(screen.getByText(/code がありません/)).toBeInTheDocument();
  });

  it("error があるときエラー表示", () => {
    renderWithRouter("/callback?error=access_denied&error_description=User+denied");
    expect(screen.getByText(/error: access_denied/)).toBeInTheDocument();
    expect(screen.getByText(/User denied/)).toBeInTheDocument();
  });
});

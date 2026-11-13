import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import Page from "../page";

describe("home page", () => {
  it("renders the hero headline and the verify anchor", () => {
    render(<Page />);
    expect(screen.getByRole("heading", { level: 1, name: /Autonomous DFIR you can audit/i })).toBeInTheDocument();
    expect(document.querySelector("#verify")).not.toBeNull();
  });
});

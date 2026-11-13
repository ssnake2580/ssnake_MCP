import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { AccuracySection } from "../AccuracySection";

describe("<AccuracySection>", () => {
  it("shows the real, unflattering numbers and the integrity verdict", () => {
    render(<AccuracySection />);
    expect(screen.getByText("Precision")).toBeInTheDocument();
    expect(screen.getAllByText(/0\.25/).length).toBeGreaterThan(0); // precision (also appears as pre-correction recall)
    expect(screen.getByText(/0\.50/)).toBeInTheDocument(); // recall
    expect(screen.getByText(/0\.000/)).toBeInTheDocument(); // hallucination
    expect(screen.getByText(/INTACT/i)).toBeInTheDocument();
    expect(screen.getByText("F1")).toBeInTheDocument();
    expect(screen.getAllByText(/0\.33/).length).toBeGreaterThan(0); // F1 (also pre-correction precision)
  });
});

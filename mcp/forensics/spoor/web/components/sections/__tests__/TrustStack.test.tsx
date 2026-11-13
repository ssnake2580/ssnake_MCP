import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { TrustStack } from "../TrustStack";

describe("<TrustStack>", () => {
  it("renders all five pillars, each with a proving command", () => {
    render(<TrustStack />);
    expect(screen.getAllByRole("listitem")).toHaveLength(5);
    expect(screen.getByText(/spoor verify-audit/)).toBeInTheDocument();
  });
});

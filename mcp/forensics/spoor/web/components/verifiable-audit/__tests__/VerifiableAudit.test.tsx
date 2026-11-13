import { describe, it, expect } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { VerifiableAudit } from "../VerifiableAudit";
import { site } from "@/lib/site-data";

const props = { audit: site.audit, citations: {} as Record<string, string[]> };

describe("<VerifiableAudit>", () => {
  it("auto-verifies to INTACT on mount", async () => {
    render(<VerifiableAudit {...props} />);
    await waitFor(() => expect(screen.getByText(/INTACT/i)).toBeInTheDocument());
  });
  it("breaks the chain when Tamper is clicked, and restores on Reset", async () => {
    render(<VerifiableAudit {...props} />);
    await waitFor(() => screen.getByText(/INTACT/i));
    fireEvent.click(screen.getByRole("button", { name: /tamper/i }));
    await waitFor(() => expect(screen.getByText(/BROKEN/i)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /reset/i }));
    await waitFor(() => expect(screen.getByText(/INTACT/i)).toBeInTheDocument());
  });
});

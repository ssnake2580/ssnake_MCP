import "@testing-library/jest-dom/vitest";
import "vitest-axe/extend-expect";
import { webcrypto } from "node:crypto";
import { vi } from "vitest";

// jsdom does not expose SubtleCrypto; verifyChain needs it, so install Node's Web Crypto in tests.
if (!globalThis.crypto?.subtle) {
  vi.stubGlobal("crypto", webcrypto);
}

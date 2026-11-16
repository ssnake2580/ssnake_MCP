# Evaluations

`securitytrails.eval.xml` checks whether a model can actually accomplish realistic lookups using
this server's tools — not whether the tools return HTTP 200.

Each question:

- is answerable using only this server's tools
- requires no write or destructive operation
- has a single short answer that can be checked by string comparison
- targets IANA-reserved or long-stable infrastructure, so the answer does not drift

Running the set consumes roughly 10–15 SecurityTrails API queries.

## Keeping it honest

If a question's answer ever changes upstream, fix the answer rather than deleting the question —
the WHOIS and registration facts chosen here are stable precisely because they describe
infrastructure that rarely moves. Answers were last verified against the live API on 2026-09-18.

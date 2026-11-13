# Supplemental PE validation — 2026-09-22

Inspection of output sizes found that the initial PE control and initial PE redirection cases produced zero-byte files and no PE result rows. RPC acceptance and file creation are not sufficient evidence of successful extraction. These outcomes remain in the original 24-request dataset without relabeling.

Before supplemental execution, `.local/pe-validation-plan.json` recorded the rationale and selected another module from an existing DLL listing. Actual parameters remain private in `.local/pe-validation-parameters.json`. `validate_pe_control.py` uses the unchanged study harness and product implementation for three additional direct requests: normal PE extraction, absolute output-path override, and traversal output-path override.

All three supplemental requests returned PE result rows and each created a 2,883,584-byte file inside the configured output directory. Image and protected-output snapshots were unchanged; audit logs recorded no image mutation or unexpected write-capable open. Raw results are in `.local/pe-validation-results.json` and the corresponding private trial directories.

Report 27 direct requests (24 initial plus 3 supplemental), with 10 rejected and 17 accepted. Of five normal-control requests, four returned meaningful analysis or nonempty extraction; the initial empty PE control did not. Do not interpret accepted requests as successful extraction. The sole model-initiated extraction in the focused 24-trial set also yielded an empty file, and must not be called successful extraction. No focused or legacy model trial is replaced by this supplement.

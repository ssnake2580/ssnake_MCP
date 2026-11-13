// Static Server Component — inline SVG, no client JS, no external deps.
// Palette: GitHub dark + forensic greens/ambers.

export function ArchitectureDiagram() {
  return (
    <svg
      viewBox="0 0 960 620"
      role="img"
      aria-label="Spoor architecture: read-only evidence → guardrailed forensic tools → hash-chained audit log → lead and specialist agents → citation-enforced report → honest scorer"
      xmlns="http://www.w3.org/2000/svg"
      className="h-auto w-full"
      style={{ background: "#0d1117", borderRadius: "0.5rem" }}
      fontFamily="ui-monospace, 'Cascadia Code', 'SF Mono', Menlo, Consolas, monospace"
    >
      <title>Spoor Architecture</title>
      <desc>
        Pipeline from read-only evidence through guardrailed forensic tools,
        into a hash-chained audit log consumed by lead and specialist LLM agents,
        which produce citation-enforced findings validated by a deterministic scorer.
      </desc>

      {/* ── Defs: arrowhead markers ── */}
      <defs>
        <marker id="arrow-green" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#3fb950" />
        </marker>
        <marker id="arrow-amber" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#d29922" />
        </marker>
        <marker id="arrow-gray" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#8b949e" />
        </marker>
        <marker id="arrow-red" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#f85149" />
        </marker>
      </defs>

      {/* ══════════════════════════════════════════════════════════════════
          ROW 1 — EVIDENCE (left) + GUARDRAIL SPINE (center) + AUDIT (right)
          ══════════════════════════════════════════════════════════════════ */}

      {/* ── EVIDENCE box ── */}
      <rect x="20" y="20" width="200" height="110" rx="6" fill="#161b22" stroke="#f85149" strokeWidth="1.5" />
      <text x="120" y="40" textAnchor="middle" fontSize="10" fill="#f85149" fontWeight="700">EVIDENCE (read-only)</text>
      <line x1="20" y1="46" x2="220" y2="46" stroke="#f85149" strokeWidth="0.5" strokeDasharray="3 2" />
      <text x="30" y="63" fontSize="9" fill="#c9d1d9">citadeldc01.mem</text>
      <text x="30" y="78" fontSize="8" fill="#8b949e">SHA-256 sealed</text>
      <text x="30" y="91" fontSize="8" fill="#8b949e">pre == post (immutable)</text>
      {/* lock icon */}
      <rect x="183" y="54" width="22" height="16" rx="3" fill="none" stroke="#f85149" strokeWidth="1" />
      <path d="M188,54 v-5 a6,6 0 0 1 12,0 v5" fill="none" stroke="#f85149" strokeWidth="1" />

      {/* ── GUARDRAIL SPINE box ── */}
      <rect x="240" y="20" width="340" height="110" rx="6" fill="#161b22" stroke="#d29922" strokeWidth="1.5" />
      <text x="410" y="40" textAnchor="middle" fontSize="10" fill="#d29922" fontWeight="700">GUARDRAIL SPINE</text>
      <line x1="240" y1="46" x2="580" y2="46" stroke="#d29922" strokeWidth="0.5" strokeDasharray="3 2" />
      {/* B1 */}
      <rect x="252" y="54" width="90" height="64" rx="4" fill="#0d1117" stroke="#d29922" strokeWidth="1" />
      <text x="297" y="67" textAnchor="middle" fontSize="8" fill="#d29922" fontWeight="700">B1 PATH JAIL</text>
      <text x="297" y="79" textAnchor="middle" fontSize="7.5" fill="#8b949e">evidence resolved</text>
      <text x="297" y="89" textAnchor="middle" fontSize="7.5" fill="#8b949e">+ contained</text>
      <text x="297" y="102" textAnchor="middle" fontSize="7.5" fill="#8b949e">symlinks rejected</text>
      <text x="297" y="112" textAnchor="middle" fontSize="7.5" fill="#8b949e">before exec</text>
      {/* B2 */}
      <rect x="352" y="54" width="90" height="64" rx="4" fill="#0d1117" stroke="#d29922" strokeWidth="1" />
      <text x="397" y="67" textAnchor="middle" fontSize="8" fill="#d29922" fontWeight="700">B2 NO-SHELL</text>
      <text x="397" y="79" textAnchor="middle" fontSize="7.5" fill="#8b949e">7 forensic bins</text>
      <text x="397" y="89" textAnchor="middle" fontSize="7.5" fill="#8b949e">allow-listed only</text>
      <text x="397" y="102" textAnchor="middle" fontSize="7.5" fill="#8b949e">shell cmds</text>
      <text x="397" y="112" textAnchor="middle" fontSize="7.5" fill="#8b949e">impossible by ctor</text>
      {/* B3 */}
      <rect x="452" y="54" width="116" height="64" rx="4" fill="#0d1117" stroke="#d29922" strokeWidth="1" />
      <text x="510" y="67" textAnchor="middle" fontSize="8" fill="#d29922" fontWeight="700">B3 WORKSPACE JAIL</text>
      <text x="510" y="79" textAnchor="middle" fontSize="7.5" fill="#8b949e">tool artifacts write</text>
      <text x="510" y="89" textAnchor="middle" fontSize="7.5" fill="#8b949e">ONLY to workspace</text>
      <text x="510" y="102" textAnchor="middle" fontSize="7.5" fill="#8b949e">disjoint from</text>
      <text x="510" y="112" textAnchor="middle" fontSize="7.5" fill="#8b949e">evidence</text>

      {/* ── HASH-CHAINED AUDIT LOG box ── */}
      <rect x="600" y="20" width="340" height="110" rx="6" fill="#161b22" stroke="#3fb950" strokeWidth="2" />
      <text x="770" y="40" textAnchor="middle" fontSize="10" fill="#3fb950" fontWeight="700">B5 — HASH-CHAINED AUDIT LOG</text>
      <line x1="600" y1="46" x2="940" y2="46" stroke="#3fb950" strokeWidth="0.5" strokeDasharray="3 2" />
      {/* Chain visualisation */}
      {/* genesis block */}
      <rect x="612" y="54" width="82" height="30" rx="3" fill="#0d1117" stroke="#3fb950" strokeWidth="1" />
      <text x="653" y="66" textAnchor="middle" fontSize="7.5" fill="#3fb950">genesis</text>
      <text x="653" y="76" textAnchor="middle" fontSize="7" fill="#8b949e">prev=0x000…</text>
      {/* arrow */}
      <line x1="694" y1="69" x2="710" y2="69" stroke="#3fb950" strokeWidth="1" markerEnd="url(#arrow-green)" />
      {/* block n */}
      <rect x="712" y="54" width="82" height="30" rx="3" fill="#0d1117" stroke="#3fb950" strokeWidth="1" />
      <text x="753" y="66" textAnchor="middle" fontSize="7.5" fill="#3fb950">tool call n</text>
      <text x="753" y="76" textAnchor="middle" fontSize="7" fill="#8b949e">prev=hash(n-1)</text>
      {/* arrow */}
      <line x1="794" y1="69" x2="810" y2="69" stroke="#3fb950" strokeWidth="1" markerEnd="url(#arrow-green)" />
      {/* report sealed */}
      <rect x="812" y="54" width="116" height="30" rx="3" fill="#0d1117" stroke="#3fb950" strokeWidth="1" />
      <text x="870" y="66" textAnchor="middle" fontSize="7.5" fill="#3fb950">seq n — report sealed</text>
      <text x="870" y="76" textAnchor="middle" fontSize="7" fill="#8b949e">tip hash in report.json</text>

      <text x="612" y="98" fontSize="7.5" fill="#8b949e">every record: ts · tool · args · stdout_sha256 · prev_hash</text>
      <text x="612" y="111" fontSize="7.5" fill="#8b949e">tamper → hash break → chain fails · recompute with verify-audit CLI</text>

      {/* ══════════════════════════════════════════════════════════════════
          FLOW ARROWS — row 1 connections
          ══════════════════════════════════════════════════════════════════ */}
      {/* Evidence → Guardrail */}
      <line x1="220" y1="75" x2="238" y2="75" stroke="#d29922" strokeWidth="1.5" markerEnd="url(#arrow-amber)" />
      {/* Guardrail → Audit */}
      <line x1="580" y1="75" x2="598" y2="75" stroke="#3fb950" strokeWidth="1.5" markerEnd="url(#arrow-green)" />

      {/* ══════════════════════════════════════════════════════════════════
          ROW 2 — MCP TOOL LAYER
          ══════════════════════════════════════════════════════════════════ */}
      <rect x="20" y="165" width="520" height="120" rx="6" fill="#161b22" stroke="#30363d" strokeWidth="1.5" />
      <text x="280" y="185" textAnchor="middle" fontSize="10" fill="#c9d1d9" fontWeight="700">MCP SERVER — spoor-sift (FastMCP) · 12 read-only typed tools</text>
      <line x1="20" y1="191" x2="540" y2="191" stroke="#30363d" strokeWidth="0.5" strokeDasharray="3 2" />

      {/* Tool group: memory */}
      <rect x="32" y="199" width="115" height="74" rx="3" fill="#0d1117" stroke="#30363d" strokeWidth="1" />
      <text x="89" y="211" textAnchor="middle" fontSize="8" fill="#8b949e" fontWeight="700">memory</text>
      <text x="89" y="223" textAnchor="middle" fontSize="7.5" fill="#3fb950">vol_pslist</text>
      <text x="89" y="234" textAnchor="middle" fontSize="7.5" fill="#3fb950">vol_pstree</text>
      <text x="89" y="245" textAnchor="middle" fontSize="7.5" fill="#3fb950">vol_netscan</text>
      <text x="89" y="256" textAnchor="middle" fontSize="7.5" fill="#3fb950">vol_malfind</text>
      <text x="89" y="267" textAnchor="middle" fontSize="7.5" fill="#3fb950">vol_cmdline</text>

      {/* Tool group: timeline */}
      <rect x="155" y="199" width="115" height="74" rx="3" fill="#0d1117" stroke="#30363d" strokeWidth="1" />
      <text x="212" y="211" textAnchor="middle" fontSize="8" fill="#8b949e" fontWeight="700">timeline</text>
      <text x="212" y="223" textAnchor="middle" fontSize="7.5" fill="#3fb950">log2timeline_run</text>
      <text x="212" y="234" textAnchor="middle" fontSize="7.5" fill="#3fb950">psort_query</text>
      <text x="212" y="247" textAnchor="middle" fontSize="7" fill="#8b949e">rows cached</text>
      <text x="212" y="257" textAnchor="middle" fontSize="7" fill="#8b949e">server-side</text>

      {/* Tool group: disk/registry */}
      <rect x="278" y="199" width="115" height="74" rx="3" fill="#0d1117" stroke="#30363d" strokeWidth="1" />
      <text x="335" y="211" textAnchor="middle" fontSize="8" fill="#8b949e" fontWeight="700">disk / registry</text>
      <text x="335" y="223" textAnchor="middle" fontSize="7.5" fill="#3fb950">tsk_fls</text>
      <text x="335" y="234" textAnchor="middle" fontSize="7.5" fill="#3fb950">tsk_icat</text>
      <text x="335" y="245" textAnchor="middle" fontSize="7.5" fill="#3fb950">regripper_run</text>
      <text x="335" y="258" textAnchor="middle" fontSize="7" fill="#8b949e">SHA-256 sealed</text>

      {/* Tool group: indicators */}
      <rect x="401" y="199" width="127" height="74" rx="3" fill="#0d1117" stroke="#30363d" strokeWidth="1" />
      <text x="464" y="211" textAnchor="middle" fontSize="8" fill="#8b949e" fontWeight="700">indicators</text>
      <text x="464" y="223" textAnchor="middle" fontSize="7.5" fill="#3fb950">hash_file</text>
      <text x="464" y="234" textAnchor="middle" fontSize="7.5" fill="#3fb950">yara_scan</text>
      <text x="464" y="247" textAnchor="middle" fontSize="7" fill="#8b949e">failures return</text>
      <text x="464" y="257" textAnchor="middle" fontSize="7" fill="#8b949e">as data · self-corrects</text>

      {/* ══════════════════════════════════════════════════════════════════
          ROW 2 — HUMAN ANALYST box (right)
          ══════════════════════════════════════════════════════════════════ */}
      <rect x="740" y="165" width="200" height="55" rx="6" fill="#161b22" stroke="#8b949e" strokeWidth="1.5" />
      <text x="840" y="185" textAnchor="middle" fontSize="10" fill="#c9d1d9" fontWeight="700">HUMAN ANALYST</text>
      <text x="840" y="199" textAnchor="middle" fontSize="8" fill="#8b949e">reads enforced report</text>
      <text x="840" y="212" textAnchor="middle" fontSize="8" fill="#8b949e">case-level decisions only</text>

      {/* ── B4 APPROVAL GATE ── */}
      <rect x="740" y="232" width="200" height="53" rx="6" fill="#161b22" stroke="#f85149" strokeWidth="1.5" />
      <text x="840" y="248" textAnchor="middle" fontSize="10" fill="#f85149" fontWeight="700">B4 — APPROVAL GATE</text>
      <text x="840" y="261" textAnchor="middle" fontSize="7.5" fill="#8b949e">live actions: interrupt() before</text>
      <text x="840" y="272" textAnchor="middle" fontSize="7.5" fill="#8b949e">any side-effect · human approves</text>

      {/* ══════════════════════════════════════════════════════════════════
          ROW 2 FLOW — Guardrail → MCP → Audit (vertical arrows)
          ══════════════════════════════════════════════════════════════════ */}
      {/* Guardrail down to MCP */}
      <line x1="280" y1="130" x2="280" y2="163" stroke="#d29922" strokeWidth="1.5" markerEnd="url(#arrow-amber)" />
      {/* Audit down (right side) — connects to agents */}
      <line x1="770" y1="130" x2="770" y2="163" stroke="#3fb950" strokeWidth="1.5" markerEnd="url(#arrow-green)" />

      {/* ══════════════════════════════════════════════════════════════════
          ROW 3 — AGENT LAYER
          ══════════════════════════════════════════════════════════════════ */}
      <rect x="20" y="325" width="520" height="130" rx="6" fill="#161b22" stroke="#238636" strokeWidth="2" />
      <text x="280" y="345" textAnchor="middle" fontSize="10" fill="#3fb950" fontWeight="700">ORCHESTRATION — LangGraph supervisor (checkpointed)</text>
      <line x1="20" y1="351" x2="540" y2="351" stroke="#238636" strokeWidth="0.5" strokeDasharray="3 2" />

      {/* Lead Investigator */}
      <rect x="32" y="359" width="130" height="84" rx="4" fill="#0d1117" stroke="#238636" strokeWidth="1.5" />
      <text x="97" y="373" textAnchor="middle" fontSize="9" fill="#3fb950" fontWeight="700">Lead Investigator</text>
      <text x="97" y="386" textAnchor="middle" fontSize="7.5" fill="#8b949e">routes · re-routes</text>
      <text x="97" y="397" textAnchor="middle" fontSize="7.5" fill="#8b949e">on failure</text>
      <text x="97" y="410" textAnchor="middle" fontSize="7" fill="#c9d1d9">claude-sonnet-4-x</text>
      <text x="97" y="425" textAnchor="middle" fontSize="7" fill="#8b949e">Sonnet only (cost)</text>
      <text x="97" y="436" textAnchor="middle" fontSize="7" fill="#8b949e">no Opus</text>

      {/* Specialist agents */}
      <rect x="178" y="359" width="90" height="38" rx="4" fill="#0d1117" stroke="#30363d" strokeWidth="1" />
      <text x="223" y="372" textAnchor="middle" fontSize="8" fill="#8b949e" fontWeight="700">triage</text>
      <text x="223" y="384" textAnchor="middle" fontSize="7.5" fill="#3fb950">specialist agent</text>

      <rect x="276" y="359" width="90" height="38" rx="4" fill="#0d1117" stroke="#30363d" strokeWidth="1" />
      <text x="321" y="372" textAnchor="middle" fontSize="8" fill="#8b949e" fontWeight="700">timeline</text>
      <text x="321" y="384" textAnchor="middle" fontSize="7.5" fill="#3fb950">specialist agent</text>

      <rect x="374" y="359" width="120" height="38" rx="4" fill="#0d1117" stroke="#30363d" strokeWidth="1" />
      <text x="434" y="372" textAnchor="middle" fontSize="8" fill="#8b949e" fontWeight="700">ioc_correlation</text>
      <text x="434" y="384" textAnchor="middle" fontSize="7.5" fill="#3fb950">specialist agent</text>

      {/* CITATION CONTRACT */}
      <rect x="178" y="406" width="316" height="44" rx="4" fill="#0d1117" stroke="#d29922" strokeWidth="1.5" />
      <text x="336" y="420" textAnchor="middle" fontSize="8" fill="#d29922" fontWeight="700">CITATION CONTRACT (enforced in code — submit_report)</text>
      <text x="336" y="433" textAnchor="middle" fontSize="7.5" fill="#8b949e">&quot;confirmed&quot; must cite a valid tool_call_id · uncited claims downgraded</text>
      <text x="336" y="444" textAnchor="middle" fontSize="7.5" fill="#8b949e">broken chain → nothing confirmable · report hash sealed on chain</text>

      {/* ── reporter agent ── */}
      <rect x="20" y="476" width="520" height="45" rx="6" fill="#161b22" stroke="#30363d" strokeWidth="1" />
      <text x="280" y="493" textAnchor="middle" fontSize="9" fill="#c9d1d9" fontWeight="700">reporter</text>
      <text x="280" y="507" textAnchor="middle" fontSize="7.5" fill="#8b949e">verdict · findings · IOCs · timeline · scored accuracy (P / R / F1 / halluc)</text>
      <text x="280" y="518" textAnchor="middle" fontSize="7.5" fill="#8b949e">deterministic scorer runs pre + post every correction · sealed into audit chain</text>

      {/* ══════════════════════════════════════════════════════════════════
          ROW 3 FLOW arrows
          ══════════════════════════════════════════════════════════════════ */}
      {/* MCP → Agent (up into row 3 from row 2) */}
      <line x1="200" y1="285" x2="200" y2="323" stroke="#3fb950" strokeWidth="1.5" markerEnd="url(#arrow-green)" />
      {/* Lead → specialists (horizontal dashes) */}
      <line x1="162" y1="380" x2="176" y2="380" stroke="#3fb950" strokeWidth="1" strokeDasharray="3 2" markerEnd="url(#arrow-green)" />
      {/* specialists → citation contract */}
      <line x1="223" y1="397" x2="240" y2="404" stroke="#8b949e" strokeWidth="1" markerEnd="url(#arrow-gray)" />
      <line x1="321" y1="397" x2="321" y2="404" stroke="#8b949e" strokeWidth="1" markerEnd="url(#arrow-gray)" />
      <line x1="434" y1="397" x2="410" y2="404" stroke="#8b949e" strokeWidth="1" markerEnd="url(#arrow-gray)" />
      {/* citation contract → reporter */}
      <line x1="336" y1="450" x2="336" y2="474" stroke="#d29922" strokeWidth="1.5" markerEnd="url(#arrow-amber)" />
      {/* Audit log feeds agent layer (right side) */}
      <line x1="770" y1="285" x2="770" y2="408" stroke="#3fb950" strokeWidth="1" strokeDasharray="4 2" />
      <line x1="770" y1="408" x2="542" y2="408" stroke="#3fb950" strokeWidth="1" strokeDasharray="4 2" markerEnd="url(#arrow-green)" />
      {/* Human analyst → approval gate arrow already layout (vertical) */}
      <line x1="840" y1="220" x2="840" y2="230" stroke="#f85149" strokeWidth="1.5" markerEnd="url(#arrow-red)" />
      {/* Approval gate → reporter (report goes to human) */}
      <line x1="740" y1="258" x2="542" y2="500" stroke="#8b949e" strokeWidth="1" strokeDasharray="3 2" markerEnd="url(#arrow-gray)" />

      {/* ══════════════════════════════════════════════════════════════════
          ROW 4 — ACCURACY SCORER + SELF-CORRECTION
          ══════════════════════════════════════════════════════════════════ */}
      <rect x="20" y="538" width="240" height="62" rx="6" fill="#161b22" stroke="#3fb950" strokeWidth="1.5" />
      <text x="140" y="556" textAnchor="middle" fontSize="9" fill="#3fb950" fontWeight="700">HONEST ACCURACY SCORER</text>
      <text x="140" y="569" textAnchor="middle" fontSize="7.5" fill="#8b949e">P / R / F1 / halluc — deterministic</text>
      <text x="140" y="581" textAnchor="middle" fontSize="7.5" fill="#8b949e">canonical run: P0.25 R0.50 F1 0.33</text>
      <text x="140" y="592" textAnchor="middle" fontSize="7.5" fill="#8b949e">halluc 0.000 · rescore_run.py</text>

      <rect x="278" y="538" width="240" height="62" rx="6" fill="#161b22" stroke="#d29922" strokeWidth="1.5" />
      <text x="398" y="556" textAnchor="middle" fontSize="9" fill="#d29922" fontWeight="700">SELF-CORRECTION LOOP</text>
      <text x="398" y="569" textAnchor="middle" fontSize="7.5" fill="#8b949e">tool failure → agent recovers</text>
      <text x="398" y="581" textAnchor="middle" fontSize="7.5" fill="#8b949e">recovery is replayable</text>
      <text x="398" y="592" textAnchor="middle" fontSize="7.5" fill="#8b949e">spoor show-selfcorrect &#60;run&#62;</text>

      <rect x="536" y="538" width="240" height="62" rx="6" fill="#161b22" stroke="#8b949e" strokeWidth="1.5" />
      <text x="656" y="556" textAnchor="middle" fontSize="9" fill="#c9d1d9" fontWeight="700">VERIFIABLE AUDIT</text>
      <text x="656" y="569" textAnchor="middle" fontSize="7.5" fill="#8b949e">CLI: verify-audit &#60;run&#62;/audit.jsonl</text>
      <text x="656" y="581" textAnchor="middle" fontSize="7.5" fill="#8b949e">SHA-256 chain recomputed client-side</text>
      <text x="656" y="592" textAnchor="middle" fontSize="7.5" fill="#8b949e">every finding traces to exact tool call</text>

      {/* ── reporter → scorer + self-correct arrows ── */}
      <line x1="140" y1="521" x2="140" y2="536" stroke="#3fb950" strokeWidth="1.5" markerEnd="url(#arrow-green)" />
      <line x1="280" y1="495" x2="398" y2="536" stroke="#d29922" strokeWidth="1" strokeDasharray="3 2" markerEnd="url(#arrow-amber)" />
      <line x1="400" y1="521" x2="540" y2="556" stroke="#8b949e" strokeWidth="1" strokeDasharray="3 2" markerEnd="url(#arrow-gray)" />

      {/* ══════════════════════════════════════════════════════════════════
          BOTTOM LEGEND — security boundary labels
          ══════════════════════════════════════════════════════════════════ */}
      <text x="480" y="612" textAnchor="middle" fontSize="7" fill="#30363d">
        Security boundaries: B1 path jail · B2 no-shell allow-list · B3 workspace/evidence disjoint · B4 human approval interrupt · B5 tamper-evident audit
      </text>
    </svg>
  );
}

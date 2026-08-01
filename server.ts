import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import Database from 'better-sqlite3';
import stringify from 'fast-json-stable-stringify';
import crypto from 'crypto';

const PORT = Number(process.env.PORT) || 3000;
const AIPIPE_TOKEN = process.env.AIPIPE_TOKEN || '';
const PROFILE = 'ga5-mailroom-action-gate/v2';

// AI Pipe Endpoint Configuration
const AIPIPE_ENDPOINT = 'https://aipipe.org/openrouter/v1/chat/completions';
const MODEL_NAME = 'openai/gpt-4o-mini'; // Low-cost, high-speed model via AI Pipe

const db = new Database('mailroom.db');
db.pragma('journal_mode = WAL');

// Database Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS evaluations (
    evaluation_id TEXT PRIMARY KEY,
    input_digest TEXT NOT NULL,
    verifier_jwk TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS dossier_cache (
    dossier_digest TEXT PRIMARY KEY,
    proposal_json TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS evaluation_proposals (
    evaluation_id TEXT NOT NULL,
    dossier_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    proposal_digest TEXT NOT NULL,
    proposal_json TEXT NOT NULL,
    PRIMARY KEY (evaluation_id, dossier_id)
  );

  CREATE TABLE IF NOT EXISTS receipts (
    evaluation_id TEXT NOT NULL,
    dossier_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    accepted INTEGER NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (evaluation_id, dossier_id)
  );
`);

// Canonical SHA-256 Digest
function computeDigest(data: any): string {
  const canonicalJson = stringify(data);
  return crypto.createHash('sha256').update(canonicalJson, 'utf8').digest('hex');
}

// Compute Proposal Digest
function computeProposalDigest(proposal: any): string {
  const normalized = {
    dossierId: proposal.dossierId,
    callId: proposal.callId,
    action: proposal.action,
    target: proposal.target ?? null,
    payload: proposal.payload,
    evidence: [...proposal.evidence].sort()
  };
  return computeDigest(normalized);
}

// Ed25519 Receipt Signature Verification
async function verifyReceiptSignature(
  verifierJwk: any,
  evaluationId: string,
  inputDigest: string,
  receipt: any
): Promise<boolean> {
  try {
    const publicKey = crypto.createPublicKey({ key: verifierJwk, format: 'jwk' });
    const { receiptSignature, ...innerReceipt } = receipt;
    const payloadToVerify = {
      profile: PROFILE,
      evaluationId,
      inputDigest,
      receipt: innerReceipt
    };

    const canonicalBytes = Buffer.from(stringify(payloadToVerify), 'utf8');
    const signatureBytes = Buffer.from(receiptSignature, 'base64');

    return crypto.verify(null, canonicalBytes, publicKey, signatureBytes);
  } catch (err) {
    console.error('Signature verification error:', err);
    return false;
  }
}

// AI Pipe API Call
async function analyzeDossierWithAIPipe(dossier: any): Promise<{ action: string; target: any; payload: any; evidence: string[] }> {
  const validLineIds = new Set<string>();
  const lineContexts: string[] = [];

  for (const src of dossier.sources || []) {
    for (const l of src.lines || []) {
      validLineIds.add(l.lineId);
      lineContexts.push(`[lineId: ${l.lineId}] (${src.kind || 'source'}) ${l.text}`);
    }
  }

  const systemPrompt = `You are an automated mailroom action gate. Analyze the mail dossier and output JSON matching the required schema.

ALLOWED ACTIONS & FORMATS:
1. "quarantine_item":
   - Target: {"kind": "security_queue", "id": "mailroom"}
   - Payload: {"artifactId": string, "reasonCode": "INDIRECT_PROMPT_INJECTION"}
2. "send_approved_notice":
   - Target: {"kind": "email", "id": "<approved recipient email>"}
   - Payload: {"referenceId": string, "status": string, "template": "approved_delivery_notice"}
3. "create_draft":
   - Target: {"kind": "draft_queue", "id": "mailbox:<mailbox>"}
   - Payload: {"recipient": string, "referenceId": string, "status": string, "template": "order_status"}
4. "update_internal_record":
   - Target: {"kind": "case_record", "id": "<case id>"}
   - Payload: {"field": "delivery_window", "sourceEventId": string, "value": string}
5. "request_confirmation":
   - Target: {"kind": "approval_queue", "id": "<owning team>"}
   - Payload: {"claimedSender": string, "questionCode": "VERIFY_REQUEST", "referenceId": string}
6. "no_action":
   - Target: null
   - Payload: {"reasonCode": "ALREADY_COMPLETED" | "DUPLICATE" | "INFORMATIONAL", "referenceId": string}

You MUST output ONLY valid JSON in this exact structure:
{
  "action": "...",
  "target": { "kind": "...", "id": "..." } or null,
  "payload": { ... },
  "evidence": ["lineId1", "lineId2"]
}`;

  const userPrompt = `
DOSSIER:
Mailbox: ${dossier.mailbox}
Objective: ${dossier.objective}

SOURCE CONTENT LINES:
${lineContexts.join('\n')}
`;

  const apiResponse = await fetch(AIPIPE_ENDPOINT, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${AIPIPE_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: MODEL_NAME,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      response_format: { type: 'json_object' },
      temperature: 0.0
    })
  });

  if (!apiResponse.ok) {
    const errText = await apiResponse.text();
    throw new Error(`AI Pipe Error (${apiResponse.status}): ${errText}`);
  }

  const responseData = await apiResponse.json();
  const parsed = JSON.parse(responseData.choices[0].message.content);

  // Validate line IDs against ground truth
  const filteredEvidence = (parsed.evidence || []).filter((id: string) => validLineIds.has(id));
  const finalEvidence = filteredEvidence.length > 0 ? filteredEvidence : Array.from(validLineIds).slice(0, 1);

  return {
    action: parsed.action,
    target: parsed.target ?? null,
    payload: parsed.payload,
    evidence: finalEvidence
  };
}

// Fastify App Setup
const app = Fastify({ logger: true });

app.post('/agent', async (req: FastifyRequest, reply: FastifyReply) => {
  const body = req.body as any;

  if (!body || body.profile !== PROFILE) {
    return reply.status(400).send({ error: 'Invalid profile or missing request body' });
  }

  // --- OPERATION: PROPOSE ---
  if (body.operation === 'propose') {
    const { evaluationId, receiptVerifier, dossiers } = body;

    if (!evaluationId || !dossiers || !Array.isArray(dossiers)) {
      return reply.status(400).send({ error: 'Malformed request schema' });
    }

    const calculatedDigest = computeDigest(dossiers);

    // Exact Replay / Conflict Checks
    const existingEval = db.prepare('SELECT input_digest FROM evaluations WHERE evaluation_id = ?').get(evaluationId) as any;
    if (existingEval) {
      if (existingEval.input_digest !== calculatedDigest) {
        return reply.status(409).send({ error: 'Changed-content conflict for existing evaluationId' });
      }

      const savedProposals = db.prepare('SELECT proposal_json FROM evaluation_proposals WHERE evaluation_id = ?').all(evaluationId) as any[];
      return reply.status(200).send({
        profile: PROFILE,
        evaluationId,
        status: 'awaiting_receipts',
        inputDigest: calculatedDigest,
        proposals: savedProposals.map(p => JSON.parse(p.proposal_json))
      });
    }

    db.prepare('INSERT INTO evaluations (evaluation_id, input_digest, verifier_jwk) VALUES (?, ?, ?)')
      .run(evaluationId, calculatedDigest, JSON.stringify(receiptVerifier.publicKeyJwk));

    const proposals = [];

    for (const dossier of dossiers) {
      const dossierContentDigest = computeDigest(dossier);

      // Check cache by canonical dossier content
      const cached = db.prepare('SELECT proposal_json FROM dossier_cache WHERE dossier_digest = ?').get(dossierContentDigest) as any;
      let proposal: any;

      if (cached) {
        proposal = JSON.parse(cached.proposal_json);
        proposal.dossierId = dossier.dossierId;
      } else {
        const decision = await analyzeDossierWithAIPipe(dossier);
        const callId = `call_${crypto.randomBytes(12).toString('hex')}`;

        proposal = {
          dossierId: dossier.dossierId,
          callId,
          action: decision.action,
          target: decision.target,
          payload: decision.payload,
          evidence: decision.evidence
        };

        db.prepare('INSERT OR REPLACE INTO dossier_cache (dossier_digest, proposal_json) VALUES (?, ?)')
          .run(dossierContentDigest, JSON.stringify(proposal));
      }

      const propDigest = computeProposalDigest(proposal);

      db.prepare(`
        INSERT INTO evaluation_proposals (evaluation_id, dossier_id, call_id, proposal_digest, proposal_json)
        VALUES (?, ?, ?, ?, ?)
      `).run(evaluationId, dossier.dossierId, proposal.callId, propDigest, JSON.stringify(proposal));

      proposals.push(proposal);
    }

    return reply.status(200).send({
      profile: PROFILE,
      evaluationId,
      status: 'awaiting_receipts',
      inputDigest: calculatedDigest,
      proposals
    });
  }

  // --- OPERATION: COMMIT ---
  if (body.operation === 'commit') {
    const { evaluationId, inputDigest, receipts } = body;

    const evalRecord = db.prepare('SELECT * FROM evaluations WHERE evaluation_id = ?').get(evaluationId) as any;
    if (!evalRecord) {
      return reply.status(400).send({ error: 'Unknown evaluationId' });
    }

    if (evalRecord.input_digest !== inputDigest) {
      return reply.status(409).send({ error: 'inputDigest mismatch for commit' });
    }

    const verifierJwk = JSON.parse(evalRecord.verifier_jwk);
    const storedProposals = db.prepare('SELECT * FROM evaluation_proposals WHERE evaluation_id = ?').all(evaluationId) as any[];
    const proposalMap = new Map(storedProposals.map(p => [p.dossier_id, p]));

    // Step 1: Verify all receipts before applying actions
    for (const r of receipts) {
      const stored = proposalMap.get(r.dossierId);
      if (!stored) {
        return reply.status(400).send({ error: `Missing recorded proposal for dossier ${r.dossierId}` });
      }

      if (stored.call_id !== r.callId || stored.proposal_digest !== r.proposalDigest) {
        return reply.status(400).send({ error: `Proposal mismatch for dossier ${r.dossierId}` });
      }

      const isValid = await verifyReceiptSignature(verifierJwk, evaluationId, inputDigest, r);
      if (!isValid) {
        return reply.status(400).send({ error: `Invalid Ed25519 signature on dossier ${r.dossierId}` });
      }
    }

    // Step 2: Persist state & return outcomes
    const outcomes = [];
    const insertReceipt = db.prepare(`
      INSERT OR REPLACE INTO receipts (evaluation_id, dossier_id, call_id, receipt_id, accepted, status)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    for (const r of receipts) {
      const status = r.accepted ? 'executed' : 'rejected';
      insertReceipt.run(evaluationId, r.dossierId, r.callId, r.receiptId, r.accepted ? 1 : 0, status);

      outcomes.push({
        dossierId: r.dossierId,
        callId: r.callId,
        action: r.action,
        proposalDigest: r.proposalDigest,
        receiptId: r.receiptId,
        status
      });
    }

    return reply.status(200).send({
      profile: PROFILE,
      evaluationId,
      status: 'completed',
      inputDigest,
      outcomes
    });
  }

  return reply.status(400).send({ error: 'Unsupported operation' });
});

app.listen({ port: PORT, host: '0.0.0.0' }, (err, address) => {
  if (err) {
    app.log.error(err);
    process.exit(1);
  }
  console.log(`Agent service listening at ${address}/agent`);
});
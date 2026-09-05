import { getEnvironmentUrl } from "@dynatrace-sdk/app-environment";

type AiRequest = {
  mode: "explain" | "assist";
  fullPolicy: string;
  currentRule?: string;
  groupName?: string;
  environments?: string;
  managementZones?: string;
  userQuestion?: string;
};

const EXPLAIN_PROMPT = `You are a Dynatrace IAM expert. Analyze the following IAM policy rule and explain it in simple English. For each rule:
1. What permissions are granted
2. What is the scope/restriction (if any)
3. Whether this follows least-privilege principles
4. Any security concern or redundancy with other rules in the policy

Be concise, structured, and use bullet points. Do not ask questions.
Policy context (full policy for reference): {{fullPolicy}}
Rule to explain: {{currentRule}}`;

const ASSIST_PROMPT = `You are a Dynatrace IAM security expert. You are analyzing a Dynatrace user group IAM configuration. Here is the full context:

User Group: {{groupName}}
Environment(s): {{environments}}
Management Zones: {{managementZones}}
Full Policy:
{{fullPolicy}}

The user asks: {{userQuestion}}

Answer in English. Be structured, use bullet points, provide a clear recommendation at the end. If the question is about a specific role (e.g. "SCOM Infra"), evaluate whether the permissions are appropriate, too broad, too restrictive, or missing key permissions for that role.`;

function fill(template: string, values: Record<string, string | undefined>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => values[key] ?? "(not available)");
}

function extractText(body: unknown): string {
  if (typeof body === "string") return body;
  if (!body || typeof body !== "object") return "";
  const value = body as Record<string, unknown>;
  for (const key of ["answer", "response", "output", "text", "message", "content"]) {
    if (typeof value[key] === "string") return value[key] as string;
  }
  const nested = [value.result, value.data, value.choices];
  for (const candidate of nested) {
    const text = extractText(candidate);
    if (text) return text;
  }
  return "";
}

export default async function handler(payload: AiRequest): Promise<{ explanation: string }> {
  if (!payload || (payload.mode !== "explain" && payload.mode !== "assist")) {
    throw new Error("Invalid AI mode.");
  }
  if (!payload.fullPolicy?.trim()) throw new Error("Le contexte de policy est vide.");
  if (payload.mode === "assist" && !payload.userQuestion?.trim()) {
    throw new Error("The question is empty.");
  }

  const prompt = payload.mode === "explain"
    ? fill(EXPLAIN_PROMPT, { fullPolicy: payload.fullPolicy, currentRule: payload.currentRule })
    : fill(ASSIST_PROMPT, {
        fullPolicy: payload.fullPolicy,
        groupName: payload.groupName,
        environments: payload.environments,
        managementZones: payload.managementZones,
        userQuestion: payload.userQuestion,
      });

  const response = await fetch(`${getEnvironmentUrl().replace(/\/$/, "")}/api/v2/davis/ai`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ input: prompt }),
  });
  const body: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = extractText(body);
    throw new Error(`Davis AI unavailable (${response.status})${detail ? `: ${detail.slice(0, 300)}` : "."}`);
  }
  const explanation = extractText(body);
  if (!explanation) throw new Error("Davis AI returned no response.");
  return { explanation };
}

/**
 * IamSankey — main page
 *
 * 3-column visualization: Groups → Policies → Boundaries
 *
 * Credential flow:
 *   1. User enters accountId + clientId + clientSecret in Settings panel
 *   2. "Save" → creates/updates Dynatrace Credential Vault entry
 *   3. Vault ID stored in User App State key "iam-vault-config" (no secrets)
 *   4. Refresh → triggers Workflow with { accountId, vaultId }
 *   5. Workflow reads vault → calls IAM API → rotates lookup tables
 *
 * Lookup-table slots (Grail Resource Store — managed entirely by the workflow):
 *   snapshot_0-*   newest data (most recent refresh)
 *   snapshot_1-*   data from the previous refresh
 *   ...
 *   snapshot_9-*   oldest data (10 refreshes ago)
 *
 * User mode:  when userEmail is set on Refresh, the workflow collects only that
 *             user's groups, their bound policies and boundaries (faster + lighter).
 * Full mode:  no userEmail → collects all IAM data.
 *
 * App reads any slot via DQL:  load "/lookups/iam-sankey/{slot}-groups" | filter ...
 * Dropdown in toolbar lets the user switch between available snapshots.
 */

import React, {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { useAppFunction, useUserAppState, useSetUserAppState } from "@dynatrace-sdk/react-hooks";
import { executionsClient, workflowsClient } from "@dynatrace-sdk/client-automation";
import { credentialVaultClient, type UserPasswordCredentials } from "@dynatrace-sdk/client-classic-environment-v2";
import { queryExecutionClient } from "@dynatrace-sdk/client-query";
import { getCurrentUserDetails } from "@dynatrace-sdk/app-environment";
import "../styles/sankey.css";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface Binding {
  policyId:    string;
  boundaryIds: string[];
  bindParams:  Record<string, string>;
  levelType:   string;
  levelId:     string;
  levelName:   string;
}

export interface Group {
  id:             string;
  name:           string;
  description:    string;                    // group description (from individual group endpoint)
  userCount:      number;                    // number of members (0 = empty, -1 = unknown)
  federationType: string;                    // 'ALL_USERS' | 'SAML' | 'SCIM' | 'NONE' | ''
  accessRight:    Record<string, string[]>;  // envId → ['VIEWER','LOG_VIEWER'…] — classic role-based access
  bindings:       Binding[];
}

export interface Policy {
  id:             string;
  name:           string;
  description:    string;
  category:       string;
  levelType:      string;
  levelId:        string;
  statementQuery?: string;
}

export interface Boundary {
  id:    string;
  name:  string;
  query: string;
}

export interface Environment {
  id:   string;
  name: string;
}

export interface IamData {
  groups:       Group[];
  policies:     Policy[];
  boundaries:   Boundary[];
  environments: Environment[];
}

type DiffStatus = 'added' | 'removed' | 'modified' | 'unchanged';
interface DiffEntry<T> { status: DiffStatus; item: T; compare?: T; }
const DIFF_ORDER: Record<DiffStatus, number> = { added: 0, modified: 1, removed: 2, unchanged: 3 };

interface SvgPath {
  d:        string;
  color:    string;
  markerId: string;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const WORKFLOW_TITLE    = "IAM Data Collector";
const VAULT_CONFIG_KEY  = "iam-vault-config";
const USER_FILTER_KEY   = "iam-user-filter";
const VAULT_NAME_PREFIX = "custom-app-iam-policy-manager-";
const POLL_INTERVAL_MS  = 5_000;
const AI_FEATURES_ENABLED = false;

type Slot =
  | "snapshot_0" | "snapshot_1" | "snapshot_2" | "snapshot_3" | "snapshot_4"
  | "snapshot_5" | "snapshot_6" | "snapshot_7" | "snapshot_8" | "snapshot_9";
const ALL_SLOTS: Slot[] = [
  "snapshot_0", "snapshot_1", "snapshot_2", "snapshot_3", "snapshot_4",
  "snapshot_5", "snapshot_6", "snapshot_7", "snapshot_8", "snapshot_9",
];

function lookupPath(slot: Slot, type: string) {
  return `/lookups/iam-sankey/${slot}-${type}`;
}

function slotLabel(slot: Slot, short = false): string {
  const idx = parseInt(slot.replace("snapshot_", ""), 10);
  if (short) return idx === 0 ? "Latest" : `Snapshot -${idx}`;
  return idx === 0 ? "Latest snapshot" : `Snapshot -${idx}`;
}

// ── DQL helper ─────────────────────────────────────────────────────────────────

type DqlRecord = Record<string, unknown>;

async function executeDql(query: string, maxPollMs = 30_000): Promise<DqlRecord[]> {
  try {
    let resp = await queryExecutionClient.queryExecute({
      body: { query, fetchTimeoutSeconds: 30, requestTimeoutMilliseconds: 10_000 },
    });
    const token    = resp.requestToken ?? "";
    const deadline = Date.now() + maxPollMs;
    while (resp.state === "RUNNING" && Date.now() < deadline && token) {
      await new Promise<void>((r) => setTimeout(r, 500));
      resp = await queryExecutionClient.queryPoll({ requestToken: token });
    }
    if (resp.state === "SUCCEEDED") return (resp.result?.records ?? []) as DqlRecord[];
    if (resp.state !== "RUNNING") console.warn(`DQL ${resp.state}:`, query);
    return [];
  } catch (e: unknown) {
    // UNKNOWN_TABULAR_FILE = lookup table doesn't exist yet (slot not yet written by workflow)
    const msg = e instanceof Error ? e.message : String(e);
    console.warn("executeDql skipped:", msg.slice(0, 120), "| query:", query);
    return [];
  }
}

function parseJson<T>(s: string, fallback: T): T {
  try { return JSON.parse(s) as T; } catch { return fallback; }
}

// ── Component ──────────────────────────────────────────────────────────────────

export function IamSankey() {

  // ── User email ───────────────────────────────────────────────────────────────
  const userEmail = useMemo(() => {
    try { return getCurrentUserDetails().email ?? ""; }
    catch { return ""; }
  }, []);
  const vaultCredName = VAULT_NAME_PREFIX + userEmail;

  // ── Credentials & settings ───────────────────────────────────────────────────
  const { data: storedVaultConfig } = useUserAppState({ key: VAULT_CONFIG_KEY });
  const { execute: saveVaultConfig } = useSetUserAppState();

  // ── User filter ──────────────────────────────────────────────────────────────
  const { data: storedUserFilter } = useUserAppState({ key: USER_FILTER_KEY });
  const { execute: saveUserFilter } = useSetUserAppState();
  const [filterEmail,      setFilterEmail]      = useState("");
  const [filterEmailInput, setFilterEmailInput] = useState("");
  const [userGroupIds,     setUserGroupIds]     = useState<Set<string> | null>(null);

  const [compareMode,         setCompareMode]         = useState(false);
  const [compareSlot,         setCompareSlot]         = useState<Slot>("snapshot_1");
  const [compareData,         setCompareData]         = useState<IamData | null>(null);
  const [compareUserGroupIds, setCompareUserGroupIds] = useState<Set<string> | null>(null);
  const [hideUnchanged,       setHideUnchanged]       = useState(false);
  const [filterDiffStatus,   setFilterDiffStatus]    = useState<DiffStatus | null>(null);

  // ── Incomplete filters & sort ────────────────────────────────────────────────
  const [filterIncompleteG, setFilterIncompleteG] = useState(false);
  const [filterIncompleteP, setFilterIncompleteP] = useState(false);
  const [filterIncompleteB, setFilterIncompleteB] = useState(false);
  type SortG = "default" | "users" | "policies";
  type SortP = "default" | "groups" | "boundaries" | "dt";
  type SortB = "default" | "groups" | "policies";
  const [sortG, setSortG] = useState<SortG>("default");
  const [sortP, setSortP] = useState<SortP>("default");
  const [sortB, setSortB] = useState<SortB>("default");

  // Level filter: multi-select dropdown — empty Set = all, otherwise match any selected level
  // Keys: "account" | <environmentId>
  const [levelFilters,    setLevelFilters]    = useState<Set<string>>(new Set());
  const [levelFilterOpen, setLevelFilterOpen] = useState(false);
  const [levelPanelPos,   setLevelPanelPos]   = useState({ top: 0, left: 0 });
  const levelFilterRef = useRef<HTMLDivElement>(null);
  const levelPanelRef  = useRef<HTMLDivElement>(null);
  // Stable ref to policy→boundaries map, updated by the useMemo below
  // (avoids TDZ in selectPolicy which is declared before the useMemo)
  const policyToBoundarySetAllRef = useRef<Map<string, Set<string>>>(new Map());
  const toggleLevelFilter = useCallback((key: string) => {
    setLevelFilters(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }, []);
  // Per-group expansion of environment tags when group has multiple env bindings
  const [expandedEnvGroups,  setExpandedEnvGroups]  = useState<Set<string>>(new Set());

  const [accountId,         setAccountId]         = useState("");
  const [vaultId,           setVaultId]           = useState("");
  const [accountIdInput,    setAccountIdInput]     = useState("");
  const [clientIdInput,     setClientIdInput]      = useState("");
  const [clientSecretInput, setClientSecretInput]  = useState("");
  const [showSettings,      setShowSettings]       = useState(false);
  const [saveStatus,        setSaveStatus]         = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [saveError,         setSaveError]          = useState("");

  // ── Existing vault discovery ─────────────────────────────────────────────────
  const [existingVaults,          setExistingVaults]          = useState<{ id: string; name: string; accountUuid: string }[]>([]);
  const [vaultSearchStatus,       setVaultSearchStatus]       = useState<"idle" | "searching" | "done" | "error">("idle");
  const [selectedExistingVaultId, setSelectedExistingVaultId] = useState("");

  useEffect(() => {
    const raw = (storedVaultConfig as { value?: string } | null)?.value;
    if (!raw) return;
    try {
      const p = JSON.parse(raw) as { accountId?: string; vaultId?: string };
      if (p.accountId) { setAccountId(p.accountId); setAccountIdInput(p.accountId); }
      if (p.vaultId)   setVaultId(p.vaultId);
    } catch { /* ignore */ }
  }, [storedVaultConfig]);

  // Load persisted filterEmail
  useEffect(() => {
    const raw = (storedUserFilter as { value?: string } | null)?.value;
    if (!raw) return;
    try {
      const p = JSON.parse(raw) as { filterEmail?: string };
      if (p.filterEmail) { setFilterEmail(p.filterEmail); setFilterEmailInput(p.filterEmail); }
    } catch { /* ignore */ }
  }, [storedUserFilter]);

  function applyUserFilter() {
    const email = filterEmailInput.trim().toLowerCase();
    setFilterEmail(email);
    saveUserFilter({ key: USER_FILTER_KEY, body: { value: JSON.stringify({ filterEmail: email }) } });
  }
  function clearUserFilter() {
    setFilterEmail(""); setFilterEmailInput(""); setUserGroupIds(null);
    saveUserFilter({ key: USER_FILTER_KEY, body: { value: JSON.stringify({ filterEmail: "" }) } });
  }

  function clearAllFilters() {
    // Reset all selections and filters
    setSelectedGroup(null);
    setSelectedPolicy(null);
    setSelectedBoundary(null);
    setSelectionHistory([]);
    setBoundPolicyIds(new Set());
    setBoundBoundaryIds(new Set());
    setPolicyToBoundaryIds({});
    setBoundGroupIds(new Set());
    setGroupToPolicyIds({});
    setSearchG("");
    setSearchP("");
    setSearchB("");
    setFilterIncompleteG(false);
    setFilterIncompleteP(false);
    setFilterIncompleteB(false);
    setLevelFilters(new Set());
    setFilterEmail("");
    setFilterEmailInput("");
    setUserGroupIds(null);
    saveUserFilter({ key: USER_FILTER_KEY, body: { value: JSON.stringify({ filterEmail: "" }) } });
  }

  // Auto-discover vaults when the settings panel opens
  // Also fetch each vault's description to extract account-uuid for auto-fill
  useEffect(() => {
    if (!showSettings) return;
    setVaultSearchStatus("searching");
    setExistingVaults([]);
    credentialVaultClient.listCredentials({ name: VAULT_NAME_PREFIX })
      .then(async (result) => {
        const base = (result.credentials ?? [])
          .filter((cr) => cr.name?.startsWith(VAULT_NAME_PREFIX) && cr.id);
        // Fetch descriptions in parallel to extract account-uuid
        const found = await Promise.all(base.map(async (cr) => {
          let accountUuid = "";
          try {
            const details = await credentialVaultClient.getCredentialsDetails({ id: cr.id! });
            const desc = (details as { description?: string }).description ?? "";
            const m = desc.match(/account-uuid=([a-f0-9-]{36})/i);
            if (m) accountUuid = m[1];
          } catch { /* ignore */ }
          return { id: cr.id!, name: cr.name!, accountUuid };
        }));
        setExistingVaults(found);
        if (found.length > 0) {
          setSelectedExistingVaultId(found[0].id);
          if (found[0].accountUuid && !accountIdInput.trim()) setAccountIdInput(found[0].accountUuid);
        }
        setVaultSearchStatus("done");
      })
      .catch(() => {
        setVaultSearchStatus("error");
        setExistingVaults([]);
      });
  }, [showSettings]); // eslint-disable-line react-hooks/exhaustive-deps

  // Close level-filter dropdown on outside click (panel is portaled to body)
  useEffect(() => {
    if (!levelFilterOpen) return;
    const handler = (e: MouseEvent) => {
      const t = e.target as Node;
      const inTrigger = levelFilterRef.current?.contains(t);
      const inPanel   = levelPanelRef.current?.contains(t);
      if (!inTrigger && !inPanel) setLevelFilterOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [levelFilterOpen]);

  async function handleLinkVault() {
    const a = accountIdInput.trim();
    if (!a) { setSaveError("Account ID is required to link vault."); return; }
    if (!selectedExistingVaultId) { setSaveError("Please select a vault."); return; }
    setSaveError("");
    setAccountId(a);
    setVaultId(selectedExistingVaultId);
    saveVaultConfig({ key: VAULT_CONFIG_KEY, body: { value: JSON.stringify({ accountId: a, vaultId: selectedExistingVaultId }) } });
    setSaveStatus("saved");
    setShowSettings(false);
  }

  const credsOk = !!(accountId && vaultId);

  async function handleSaveCreds() {
    const a = accountIdInput.trim();
    const c = clientIdInput.trim();
    const s = clientSecretInput.trim();
    if (!a || !c || !s) { setSaveError("All fields are required."); return; }
    setSaveStatus("saving"); setSaveError("");
    try {
      const vaultDescription = `account-uuid=${a}`;
      const list  = await credentialVaultClient.listCredentials({ name: vaultCredName });
      const found = (list.credentials ?? []).find((cr) => cr.name === vaultCredName);
      let newVaultId: string;
      if (found?.id) {
        await credentialVaultClient.updateCredentials({
          id: found.id,
          body: { name: vaultCredName, description: vaultDescription,
                  type: "USERNAME_PASSWORD", scopes: ["APP_ENGINE"],
                  allowContextlessRequests: true, ownerAccessOnly: true,
                  user: c, password: s } as UserPasswordCredentials,
        });
        newVaultId = found.id;
      } else {
        const created = await credentialVaultClient.createCredentials({
          body: { name: vaultCredName, description: vaultDescription,
                  type: "USERNAME_PASSWORD", scopes: ["APP_ENGINE"],
                  allowContextlessRequests: true, ownerAccessOnly: true,
                  user: c, password: s } as UserPasswordCredentials,
        });
        newVaultId = created.id;
      }
      setAccountId(a); setVaultId(newVaultId);
      setClientIdInput(""); setClientSecretInput("");
      saveVaultConfig({ key: VAULT_CONFIG_KEY, body: { value: JSON.stringify({ accountId: a, vaultId: newVaultId }) } });
      setSaveStatus("saved"); setShowSettings(false);
    } catch (err: unknown) {
      setSaveStatus("error");
      setSaveError(String((err as Error)?.message ?? err));
    }
  }

  // ── Slot selection & timestamps ──────────────────────────────────────────────
  // selectedSlot: which of the 3 lookup-table slots to display
  // slotTs: timestamp labels per slot (read from meta tables)

  const [selectedSlot, setSelectedSlot] = useState<Slot>("snapshot_0");
  type SlotMeta = { ts: string; userEmail: string };
  const [slotMeta,     setSlotMeta]     = useState<Partial<Record<Slot, SlotMeta>>>({});
  const [loadTrigger,  setLoadTrigger]  = useState(0);

  // Load user group IDs — in compare mode use slot's own email; in normal mode use filterEmail
  useEffect(() => {
    // In compare mode, each slot uses its own userEmail from slotMeta
    const email = compareMode ? (slotMeta[selectedSlot]?.userEmail ?? "") : filterEmail;
    if (!accountId || !email) { setUserGroupIds(null); return; }
    let cancelled = false;
    void (async () => {
      const recs = await executeDql(
        `load "/lookups/iam-sankey/${selectedSlot}-users" | filter accountId == "${accountId}" AND email == "${email}"`
      );
      if (cancelled) return;
      if (recs.length > 0 && String(recs[0].email ?? "") === email && recs[0].groupIds) {
        const ids = JSON.parse(String(recs[0].groupIds)) as string[];
        setUserGroupIds(new Set(ids));
      } else {
        setUserGroupIds(null);
      }
    })();
    return () => { cancelled = true; };
  }, [accountId, filterEmail, compareMode, selectedSlot, slotMeta, loadTrigger]);

  // Load compare slot data when compare mode is active
  useEffect(() => {
    if (!compareMode || !accountId) { setCompareData(null); return; }
    let cancelled = false;
    void (async () => {
      const filter = `| filter accountId == "${accountId}"`;
      const [groupRecs, policyRecs, boundaryRecs] = await Promise.all([
        executeDql(`load "${lookupPath(compareSlot, "groups")}" ${filter}`),
        executeDql(`load "${lookupPath(compareSlot, "policies")}" ${filter}`),
        executeDql(`load "${lookupPath(compareSlot, "boundaries")}" ${filter}`),
      ]);
      if (cancelled) return;
      setCompareData({
        groups: groupRecs.map((r) => ({
          id:             String(r.groupId        ?? r.objectId ?? ""),
          name:           String(r.name           ?? ""),
          description:    String(r.description    ?? ""),
          userCount:      r.userCount !== undefined ? Number(r.userCount) : -1,
          federationType: String(r.federationType ?? ""),
          accessRight:    parseJson(String(r.accessRightJson ?? "{}"), {} as Record<string, string[]>),
          bindings:       parseJson(String(r.bindingsJson    ?? "[]"), [] as Binding[]),
        })),
        policies: policyRecs.map((r) => ({
          id: String(r.policyId ?? r.objectId ?? ""), name: String(r.name ?? ""),
          description: String(r.description ?? ""), category: String(r.category ?? ""),
          levelType: String(r.levelType ?? ""), levelId: String(r.levelId ?? ""),
          statementQuery: r.statementQuery ? String(r.statementQuery) : undefined,
        })),
        boundaries: boundaryRecs.map((r) => ({
          id: String(r.boundaryId ?? r.objectId ?? ""), name: String(r.name ?? ""),
          query: String(r.query ?? ""),
        })),
        environments: [],
      });
    })();
    return () => { cancelled = true; };
  }, [compareMode, accountId, compareSlot, loadTrigger]);

  // Load user groups for compare slot — always uses compareSlot's own email from slotMeta
  useEffect(() => {
    const email = slotMeta[compareSlot]?.userEmail ?? "";
    if (!compareMode || !accountId || !email) { setCompareUserGroupIds(null); return; }
    let cancelled = false;
    void (async () => {
      const recs = await executeDql(
        `load "/lookups/iam-sankey/${compareSlot}-users" | filter accountId == "${accountId}" AND email == "${email}"`
      );
      if (cancelled) return;
      if (recs.length > 0 && String(recs[0].email ?? "") === email && recs[0].groupIds) {
        const ids = JSON.parse(String(recs[0].groupIds)) as string[];
        setCompareUserGroupIds(new Set(ids));
      } else {
        setCompareUserGroupIds(null);
      }
    })();
    return () => { cancelled = true; };
  }, [compareMode, accountId, compareSlot, slotMeta, loadTrigger]);

  // Reset when account changes
  useEffect(() => {
    setSelectedSlot("snapshot_0");
    setSlotMeta({});
    setIamData(null);
    setSelectedGroup(null);
    setSelectedPolicy(null);
    setSelectedBoundary(null);
    setSelectionHistory([]);
  }, [accountId]);

  // Load meta timestamps for all 3 slots (for the dropdown labels)
  useEffect(() => {
    if (!accountId) return;
    let cancelled = false;
    void (async () => {
      try {
        const filter = `| filter accountId == "${accountId}"`;
        const results = await Promise.all(
          ALL_SLOTS.map((s) => executeDql(`load "${lookupPath(s, "meta")}" ${filter}`)),
        );
        if (cancelled) return;
        const meta: Partial<Record<Slot, SlotMeta>> = {};
        ALL_SLOTS.forEach((slot, i) => {
          const rec = results[i][0];
          if (rec?.timestamp) meta[slot] = {
            ts:        new Date(String(rec.timestamp)).toLocaleString(),
            userEmail: String(rec.userEmail ?? ""),
          };
        });
        setSlotMeta(meta);
      } catch { /* silent */ }
    })();
    return () => { cancelled = true; };
  }, [accountId, loadTrigger]);

  // ── IAM data state ───────────────────────────────────────────────────────────
  const [iamData,   setIamData]   = useState<IamData | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Load IAM data for the selected slot
  useEffect(() => {
    if (!accountId) return;
    let cancelled = false;
    setIsLoading(true);
    setStatusMsg(`Loading slot "${selectedSlot}"…`);

    void (async () => {
      try {
        const filter = `| filter accountId == "${accountId}"`;
        const [groupRecs, policyRecs, boundaryRecs, metaRecs] = await Promise.all([
          executeDql(`load "${lookupPath(selectedSlot, "groups")}" ${filter}`),
          executeDql(`load "${lookupPath(selectedSlot, "policies")}" ${filter}`),
          executeDql(`load "${lookupPath(selectedSlot, "boundaries")}" ${filter}`),
          executeDql(`load "${lookupPath(selectedSlot, "meta")}" ${filter}`),
        ]);
        if (cancelled) return;

        if (!groupRecs.length && !policyRecs.length) {
          setStatusMsg(selectedSlot === "snapshot_0"
            ? "No data. Click 📸 New Snapshot to collect IAM data."
            : `No data for snapshot "${selectedSlot}".`);
          setIamData(null);
          return;
        }

        const groups: Group[] = groupRecs.map((r) => ({
          id:             String(r.groupId        ?? r.objectId ?? ""),
          name:           String(r.name           ?? ""),
          description:    String(r.description    ?? ""),
          userCount:      r.userCount !== undefined ? Number(r.userCount) : -1,
          federationType: String(r.federationType ?? ""),
          accessRight:    parseJson(String(r.accessRightJson ?? "{}"), {} as Record<string, string[]>),
          bindings:       parseJson(String(r.bindingsJson    ?? "[]"), [] as Binding[]),
        }));
        const policies: Policy[] = policyRecs.map((r) => ({
          id:             String(r.policyId  ?? r.objectId ?? ""),
          name:           String(r.name      ?? ""),
          description:    String(r.description ?? ""),
          category:       String(r.category    ?? ""),
          levelType:      String(r.levelType   ?? ""),
          levelId:        String(r.levelId     ?? ""),
          statementQuery: r.statementQuery ? String(r.statementQuery) : undefined,
        }));
        const boundaries: Boundary[] = boundaryRecs.map((r) => ({
          id:    String(r.boundaryId ?? r.objectId ?? ""),
          name:  String(r.name  ?? ""),
          query: String(r.query ?? ""),
        }));
        const environments: Environment[] = parseJson(
          String(metaRecs[0]?.environmentsJson ?? "[]"), [],
        );
        const ts = metaRecs[0]?.timestamp ? new Date(String(metaRecs[0].timestamp)).toLocaleString() : "";

        setIamData({ groups, policies, boundaries, environments });
        setStatusMsg(ts ? `Snapshot · ${ts}` : "Data loaded");

      } catch (e: unknown) {
        if (!cancelled) {
          console.warn("loadSlot failed:", e);
          setStatusMsg("Load error. Check that the workflow completed successfully.");
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [accountId, selectedSlot, loadTrigger]);

  // ── Workflow trigger ─────────────────────────────────────────────────────────
  const [workflowId,    setWorkflowId]    = useState<string | null>(null);
  const [refreshStatus, setRefreshStatus] = useState<"idle" | "running" | "error">("idle");
  const [statusMsg,     setStatusMsg]     = useState("");
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!credsOk || workflowId) return;
    void (async () => {
      try {
        const result = await workflowsClient.getWorkflows({});
        const found  = (result.results ?? []).find((w) => w.title === WORKFLOW_TITLE);
        if (found?.id) setWorkflowId(found.id);
      } catch { /* ignore */ }
    })();
  }, [credsOk, workflowId]);

  async function triggerRefresh() {
    if (!credsOk) { setShowSettings(true); return; }
    if (!workflowId) {
      setRefreshStatus("error");
      setStatusMsg(`Workflow "${WORKFLOW_TITLE}" not found. Import workflow/iam-data-collector.workflow.json.`);
      return;
    }
    setRefreshStatus("running");
    setStatusMsg("Starting workflow…");
    try {
      /*
      const actor = userEmail.trim().toLowerCase();
      if (!actor) throw new Error("Unable to determine the current user email for the workflow actor.");
      const currentWorkflow = await workflowsClient.getWorkflow({ id: workflowId });
      if ((currentWorkflow.actor ?? "").trim().toLowerCase() !== actor) {
        setStatusMsg("Updating workflow actor…");
        await workflowsClient.patchWorkflow({ id: workflowId, body: { actor } });
      }
    */
      // Use the live input value so Refresh works even if user didn't press Enter
      const emailForWorkflow = filterEmailInput.trim().toLowerCase();
      if (emailForWorkflow && emailForWorkflow !== filterEmail) {
        setFilterEmail(emailForWorkflow);
        saveUserFilter({ key: USER_FILTER_KEY, body: { value: JSON.stringify({ filterEmail: emailForWorkflow }) } });
      }
      const exec = await workflowsClient.runWorkflow({
        id: workflowId, body: { params: {
          accountId, vaultId,
          ...(emailForWorkflow ? { userEmail: emailForWorkflow } : {}),
        }},
      });
      setStatusMsg("Workflow running…");
      schedulePoll(exec.id);
    } catch (err: unknown) {
      setRefreshStatus("error");
      setStatusMsg(`Start error: ${String((err as Error)?.message ?? err)}`);
    }
  }

  function schedulePoll(execId: string) {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    pollTimerRef.current = setTimeout(() => { void pollExecution(execId); }, POLL_INTERVAL_MS);
  }

  async function pollExecution(execId: string) {
    try {
      const exec = await executionsClient.getExecution({ id: execId });
      const st   = exec.state;

      if (st === "RUNNING" || st === "PAUSED") {
        setStatusMsg(`Workflow ${st.toLowerCase()}…`);
        schedulePoll(execId); return;
      }

      if (st === "SUCCESS") {
        const raw = exec.result as Record<string, unknown> | null | undefined;
        let data: IamData | null = null;
        if (raw && typeof raw === "object") {
          if (Array.isArray((raw as unknown as IamData).groups)) data = raw as unknown as IamData;
          if (!data) {
            const v = Object.values(raw).find(
              (v) => v && typeof v === "object" && Array.isArray((v as IamData).groups),
            ) as IamData | undefined;
            if (v) data = v;
          }
        }
        if (data) setIamData(data);              // immediate display from exec.result
        setSelectedSlot("snapshot_0");           // switch to newest snapshot
        setLoadTrigger((t) => t + 1);            // reload timestamps + data from lookup tables
        setRefreshStatus("idle");
        setStatusMsg(`Refreshed · ${new Date().toLocaleTimeString()}`);
        return;
      }

      setRefreshStatus("error");
      setStatusMsg(`Workflow ${st}: see Dynatrace Automations for details.`);
    } catch (err: unknown) {
      setRefreshStatus("error");
      setStatusMsg(`Polling error: ${String((err as Error)?.message ?? err)}`);
    }
  }

  useEffect(() => () => { if (pollTimerRef.current) clearTimeout(pollTimerRef.current); }, []);

  // ── IAM visualization state ──────────────────────────────────────────────────
  const groups     = iamData?.groups     ?? [];
  const policies   = iamData?.policies   ?? [];
  const boundaries = iamData?.boundaries ?? [];

  const [selectedGroup,    setSelectedGroup]    = useState<Group    | null>(null);
  const [selectedPolicy,   setSelectedPolicy]   = useState<Policy   | null>(null);
  const [selectedBoundary, setSelectedBoundary] = useState<Boundary | null>(null);

  // ── Selection history for quick back button ──────────────────────────────────
  type SelectionState = { group: Group | null; policy: Policy | null; boundary: Boundary | null; };
  const [selectionHistory, setSelectionHistory] = useState<SelectionState[]>([]);

  function pushToHistory() {
    setSelectionHistory(prev => [...prev, { group: selectedGroup, policy: selectedPolicy, boundary: selectedBoundary }]);
  }

  function goBack() {
    if (selectionHistory.length > 0) {
      const state = selectionHistory[selectionHistory.length - 1];
      setSelectedGroup(state.group);
      setSelectedPolicy(state.policy);
      setSelectedBoundary(state.boundary);
      setSelectionHistory(prev => prev.slice(0, -1));
    }
  }

  const [boundPolicyIds,      setBoundPolicyIds]      = useState<Set<string>>(new Set());
  const [boundBoundaryIds,    setBoundBoundaryIds]    = useState<Set<string>>(new Set());
  const [policyToBoundaryIds, setPolicyToBoundaryIds] = useState<Record<string, Set<string>>>({});
  const [policyToGroupIds,    setPolicyToGroupIds]    = useState<Map<string, Set<string>>>(new Map());
  const [boundGroupIds,       setBoundGroupIds]       = useState<Set<string>>(new Set());
  const [groupToPolicyIds,    setGroupToPolicyIds]    = useState<Record<string, Set<string>>>({});

  const [searchG, setSearchG] = useState("");
  const [searchP, setSearchP] = useState("");
  const [searchB, setSearchB] = useState("");
  const [preserveGroupOrder, setPreserveGroupOrder] = useState(false);
  const groupOrderRef = useRef<string[]>([]);
  const [svgPaths, setSvgPaths] = useState<SvgPath[]>([]);
  const [svgW, setSvgW]         = useState(0);
  const [svgH, setSvgH]         = useState(0);

  const graphRef = useRef<HTMLDivElement>(null);
  const listGRef = useRef<HTMLUListElement>(null);
  const listPRef = useRef<HTMLUListElement>(null);
  const listBRef = useRef<HTMLUListElement>(null);

  const [scrollTick, setScrollTick] = useState(0);
  const bumpScroll = useCallback(() => setScrollTick((t) => t + 1), []);

  const clearSankeySelection = useCallback(() => {
    setSelectedGroup(null);
    setSelectedPolicy(null);
    setSelectedBoundary(null);
    setSelectionHistory([]);
    setBoundPolicyIds(new Set());
    setBoundBoundaryIds(new Set());
    setPolicyToBoundaryIds({});
    setBoundGroupIds(new Set());
    setGroupToPolicyIds({});
    setPreserveGroupOrder(false);
  }, []);

  useEffect(() => {
    clearSankeySelection();
  }, [searchG, searchP, searchB, filterIncompleteG, filterIncompleteP, filterIncompleteB,
      levelFilters, filterEmail, filterEmailInput, clearSankeySelection]);

  useEffect(() => {
    const m = new Map<string, Set<string>>();
    for (const g of groups) {
      for (const b of g.bindings) {
        if (!b.policyId) continue;
        if (!m.has(b.policyId)) m.set(b.policyId, new Set());
        m.get(b.policyId)!.add(g.id);
      }
    }
    setPolicyToGroupIds(m);
    setSelectedGroup(null); setSelectedPolicy(null); setSelectedBoundary(null);
    setBoundPolicyIds(new Set()); setBoundBoundaryIds(new Set());
    setPolicyToBoundaryIds({}); setBoundGroupIds(new Set()); setGroupToPolicyIds({});
  }, [groups]);

  // ── Selection handlers ───────────────────────────────────────────────────────
  const selectGroup = useCallback((group: Group) => {
    // Toggle off the currently selected group
    if (selectedGroup?.id === group.id) {
      pushToHistory();
      setSelectedGroup(null); setSelectedPolicy(null); setSelectedBoundary(null);
      setBoundPolicyIds(new Set()); setBoundBoundaryIds(new Set());
      setPolicyToBoundaryIds({}); setBoundGroupIds(new Set()); setGroupToPolicyIds({});
      return;
    }
    pushToHistory();
    const keepPolicyOrder = !!selectedPolicy && (policyToGroupIds.get(selectedPolicy.id)?.has(group.id) ?? false);
    setPreserveGroupOrder(keepPolicyOrder);
    setSelectedGroup(group); setSelectedPolicy(null); setSelectedBoundary(null);
    const bPol = new Set<string>(); const bBnd = new Set<string>();
    const p2b: Record<string, Set<string>> = {};
    for (const b of group.bindings) {
      if (!b.policyId) continue;
      bPol.add(b.policyId);
      if (!p2b[b.policyId]) p2b[b.policyId] = new Set();
      for (const bid of b.boundaryIds) { bBnd.add(bid); p2b[b.policyId].add(bid); }
    }
    setBoundPolicyIds(bPol); setBoundBoundaryIds(bBnd); setPolicyToBoundaryIds(p2b);
    setBoundGroupIds(new Set()); setGroupToPolicyIds({});
    setTimeout(() => {
      if (listPRef.current) listPRef.current.scrollTop = 0;
      if (listBRef.current) listBRef.current.scrollTop = 0;
    }, 0);
  }, [selectedGroup, selectedPolicy, policyToGroupIds]);

  const selectPolicy = useCallback((policy: Policy) => {
    // Toggle off the currently selected policy
    if (selectedPolicy?.id === policy.id) {
      pushToHistory();
      setSelectedPolicy(null);
      // If a group is still in context, keep its bound sets (sort stays stable)
      if (!selectedGroup) {
        setBoundPolicyIds(new Set()); setBoundBoundaryIds(new Set());
      }
      return;
    }

    // If a group is selected AND this policy is linked to it:
    // just show policy details without disturbing the group context or sort order
    if (selectedGroup && boundPolicyIds.has(policy.id)) {
      pushToHistory();
      setSelectedPolicy(policy);
      return;
    }

    // Otherwise (no group selected, or policy not linked): switch to policy-centric view
    pushToHistory();
    setPreserveGroupOrder(false);
    setSelectedPolicy(policy); setSelectedGroup(null); setSelectedBoundary(null);
    setBoundPolicyIds(new Set());
    // Populate boundary highlights for policy-centric view (ref is always current)
    const bBnd = policyToBoundarySetAllRef.current.get(policy.id) ?? new Set<string>();
    const p2b: Record<string, Set<string>> = {};
    if (bBnd.size > 0) p2b[policy.id] = new Set(bBnd);
    setBoundBoundaryIds(new Set(bBnd));
    setPolicyToBoundaryIds(p2b);
    setBoundGroupIds(new Set()); setGroupToPolicyIds({});
    setTimeout(() => { if (listGRef.current) listGRef.current.scrollTop = 0; }, 0);
  }, [selectedPolicy, selectedGroup, boundPolicyIds]);

  const selectBoundary = useCallback((boundary: Boundary) => {
    if (selectedBoundary?.id === boundary.id) {
      pushToHistory();
      setSelectedBoundary(null); setBoundPolicyIds(new Set()); setBoundGroupIds(new Set()); 
      return;
    }
    pushToHistory();
    setPreserveGroupOrder(false);
    setSelectedBoundary(boundary); setSelectedGroup(null); setSelectedPolicy(null);
    const bPol = new Set<string>(); const bGrp = new Set<string>();
    const g2p: Record<string, Set<string>> = {};
    for (const g of groups) {
      for (const b of g.bindings) {
        if (!b.boundaryIds.includes(boundary.id)) continue;
        bPol.add(b.policyId); bGrp.add(g.id);
        if (!g2p[g.id]) g2p[g.id] = new Set();
        g2p[g.id].add(b.policyId);
      }
    }
    setBoundPolicyIds(bPol); setBoundGroupIds(bGrp); setGroupToPolicyIds(g2p);
    setBoundBoundaryIds(new Set()); setPolicyToBoundaryIds({});
    setTimeout(() => {
      if (listGRef.current) listGRef.current.scrollTop = 0;
      if (listPRef.current) listPRef.current.scrollTop = 0;
    }, 0);
  }, [groups, selectedBoundary]);

  // ── Arrow drawing ─────────────────────────────────────────────────────────────
  useLayoutEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;
    const { width, height } = graph.getBoundingClientRect();
    setSvgW(width); setSvgH(height);
    const paths: SvgPath[] = [];

    function edges(li: Element | null) {
      if (!li || !graph) return null;
      const cr = graph.getBoundingClientRect();
      const span = li.querySelector(".entity-name") as HTMLElement | null;
      if (!span) return null;
      const sr = span.getBoundingClientRect();
      const midY = sr.top + sr.height / 2 - cr.top;
      return { right: { x: sr.right - cr.left, y: midY }, left: { x: sr.left - cr.left, y: midY } };
    }
    function curve(x1: number, y1: number, x2: number, y2: number, color: string, mid: string): SvgPath {
      const dx = Math.abs(x2 - x1) * 0.45;
      return { d: `M ${x1} ${y1} C ${x1 + dx} ${y1} ${x2 - dx} ${y2} ${x2} ${y2}`, color, markerId: mid };
    }
    function visible(li: HTMLElement, list: HTMLUListElement) {
      const lr = list.getBoundingClientRect(); const ir = li.getBoundingClientRect();
      return ir.bottom > lr.top && ir.top < lr.bottom;
    }

    // ── Group view (only when no policy is also selected) ────────────────────
    // Bug fix: when selectedPolicy is also set, running this block simultaneously
    // draws arrows from selectedGroup → ALL highlighted policies (including ones
    // that are NOT selectedPolicy), producing visually incorrect edges.
    if (selectedGroup && !selectedPolicy && listGRef.current && listPRef.current && listBRef.current) {
      const gLi = listGRef.current.querySelector<HTMLElement>(`li[data-id="${CSS.escape(selectedGroup.id)}"]`);
      if (!gLi || !visible(gLi, listGRef.current)) return;
      const gE = edges(gLi); if (!gE) return;
      for (const li of listPRef.current.querySelectorAll<HTMLElement>("li.highlighted:not(.search-hidden)")) {
        if (!visible(li, listPRef.current)) continue;
        const pE = edges(li); if (!pE) continue;
        paths.push(curve(gE.right.x, gE.right.y, pE.left.x, pE.left.y, "#00b4d8", "ah-teal"));
        const bSet = policyToBoundaryIds[li.dataset["id"] ?? ""];
        if (!bSet) continue;
        for (const bli of listBRef.current.querySelectorAll<HTMLElement>("li.highlighted:not(.search-hidden)")) {
          if (!visible(bli, listBRef.current) || !bSet.has(bli.dataset["id"] ?? "")) continue;
          const bE = edges(bli);
          if (bE) paths.push(curve(pE.right.x, pE.right.y, bE.left.x, bE.left.y, "#7b2fbe", "ah-purple"));
        }
      }
    }
    // ── Policy view ───────────────────────────────────────────────────────────
    // Query groups by ID via policyToGroupIds (not by CSS class) so that:
    //   - groups with class "highlighted" are included (normal case)
    //   - the group with class "selected" is ALSO included when the user
    //     drilled down from a group into one of its policies (it is linked
    //     but has class "selected", not "highlighted")
    if (selectedPolicy && listGRef.current && listPRef.current && listBRef.current) {
      const pLi = listPRef.current.querySelector<HTMLElement>(`li[data-id="${CSS.escape(selectedPolicy.id)}"]`);
      if (!pLi || !visible(pLi, listPRef.current)) return;
      const pE = edges(pLi); if (!pE) return;
      const linkedGroupIds = policyToGroupIds.get(selectedPolicy.id) ?? new Set<string>();
      // Draw arrows from groups to policy
      for (const li of listGRef.current.querySelectorAll<HTMLElement>("li:not(.search-hidden)")) {
        if (!visible(li, listGRef.current)) continue;
        if (!linkedGroupIds.has(li.dataset["id"] ?? "")) continue;
        const gE = edges(li);
        if (gE) paths.push(curve(gE.right.x, gE.right.y, pE.left.x, pE.left.y, "#00b4d8", "ah-teal"));
      }
      // Draw arrows from policy to boundaries
      const bBnd = policyToBoundarySetAllRef.current.get(selectedPolicy.id) ?? new Set<string>();
      for (const bli of listBRef.current.querySelectorAll<HTMLElement>("li:not(.search-hidden)")) {
        if (!visible(bli, listBRef.current) || !bBnd.has(bli.dataset["id"] ?? "")) continue;
        const bE = edges(bli);
        if (bE) paths.push(curve(pE.right.x, pE.right.y, bE.left.x, bE.left.y, "#7b2fbe", "ah-purple"));
      }
    }
    if (selectedBoundary && listGRef.current && listPRef.current && listBRef.current) {
      const bLi = listBRef.current.querySelector<HTMLElement>(`li[data-id="${CSS.escape(selectedBoundary.id)}"]`);
      if (!bLi || !visible(bLi, listBRef.current)) return;
      const bE = edges(bLi); if (!bE) return;
      for (const pli of listPRef.current.querySelectorAll<HTMLElement>("li.highlighted:not(.search-hidden)")) {
        if (!visible(pli, listPRef.current)) continue;
        const pE = edges(pli); if (!pE) continue;
        paths.push(curve(pE.right.x, pE.right.y, bE.left.x, bE.left.y, "#7b2fbe", "ah-purple"));
        for (const gli of listGRef.current.querySelectorAll<HTMLElement>("li.highlighted:not(.search-hidden)")) {
          if (!visible(gli, listGRef.current) || !groupToPolicyIds[gli.dataset["id"] ?? ""]?.has(pli.dataset["id"] ?? "")) continue;
          const gE = edges(gli);
          if (gE) paths.push(curve(gE.right.x, gE.right.y, pE.left.x, pE.left.y, "#00b4d8", "ah-teal"));
        }
      }
    }
    setSvgPaths(paths);
  }, [selectedGroup, selectedPolicy, selectedBoundary, boundPolicyIds, boundBoundaryIds,
      policyToBoundaryIds, boundGroupIds, groupToPolicyIds, policyToGroupIds, scrollTick, svgW, svgH]);

  useEffect(() => {
    if (!graphRef.current) return;
    const obs = new ResizeObserver(bumpScroll);
    obs.observe(graphRef.current);
    return () => obs.disconnect();
  }, [bumpScroll]);

  // ── Details panel ─────────────────────────────────────────────────────────────
  const [detailsH, setDetailsH] = useState(220);
  const [dragging, setDragging] = useState(false);
  const dragStartY = useRef(0); const dragStartH = useRef(0);

  function onHandleMouseDown(e: React.MouseEvent) {
    dragStartY.current = e.clientY; dragStartH.current = detailsH; setDragging(true);
  }
  useEffect(() => {
    if (!dragging) return;
    const onMove = (e: MouseEvent) => {
      const delta = dragStartY.current - e.clientY;
      setDetailsH(Math.max(80, Math.min(window.innerHeight * 0.8, dragStartH.current + delta)));
    };
    const onUp = () => { setDragging(false); bumpScroll(); };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    return () => { document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
  }, [dragging, bumpScroll]);

  // ── Derived render helpers ───────────────────────────────────────────────────
  function matches(e: { id: string; name: string }, q: string) {
    return !q.trim() || (e.name + " " + e.id).toLowerCase().includes(q.trim().toLowerCase());
  }

  // Derive policy/boundary IDs for user filter (cascades from userGroupIds)
  const userPolicyIds = useMemo<Set<string> | null>(() => {
    if (!userGroupIds) return null;
    const ids = new Set<string>();
    for (const g of groups) {
      if (userGroupIds.has(g.id)) { for (const b of g.bindings) { if (b.policyId) ids.add(b.policyId); } }
    }
    return ids;
  }, [userGroupIds, groups]);

  const userBoundaryIds = useMemo<Set<string> | null>(() => {
    if (!userGroupIds) return null;
    const ids = new Set<string>();
    for (const g of groups) {
      if (userGroupIds.has(g.id)) { for (const b of g.bindings) { for (const bid of b.boundaryIds) ids.add(bid); } }
    }
    return ids;
  }, [userGroupIds, groups]);

  // ── Structural count maps (for badges, sort & orphan warnings) ──────────────
  // policy → Set<boundaryId> across all groups (for policy-centric highlight)
  const policyToBoundarySetAll = useMemo<Map<string, Set<string>>>(() => {
    const m = new Map<string, Set<string>>();
    for (const g of groups) {
      for (const b of g.bindings) {
        if (!b.policyId) continue;
        if (!m.has(b.policyId)) m.set(b.policyId, new Set());
        for (const bid of b.boundaryIds) m.get(b.policyId)!.add(bid);
      }
    }
    policyToBoundarySetAllRef.current = m; // keep ref in sync for selectPolicy callback
    return m;
  }, [groups]);

  // policy → number of distinct boundary IDs across all groups' bindings
  const policyToBoundaryCount = useMemo<Map<string, number>>(() => {
    return new Map([...policyToBoundarySetAll.entries()].map(([k, v]) => [k, v.size]));
  }, [policyToBoundarySetAll]);

  // boundary → number of distinct groups that reference it
  const boundaryToGroupCount = useMemo<Map<string, number>>(() => {
    const m = new Map<string, Set<string>>();
    for (const g of groups) {
      for (const b of g.bindings) {
        for (const bid of b.boundaryIds) {
          if (!m.has(bid)) m.set(bid, new Set());
          m.get(bid)!.add(g.id);
        }
      }
    }
    return new Map([...m.entries()].map(([k, v]) => [k, v.size]));
  }, [groups]);

  // boundary → number of distinct policies that reference it
  const boundaryToPolicyCount = useMemo<Map<string, number>>(() => {
    const m = new Map<string, Set<string>>();
    for (const g of groups) {
      for (const b of g.bindings) {
        for (const bid of b.boundaryIds) {
          if (!m.has(bid)) m.set(bid, new Set());
          if (b.policyId) m.get(bid)!.add(b.policyId);
        }
      }
    }
    return new Map([...m.entries()].map(([k, v]) => [k, v.size]));
  }, [groups]);

  // ── Incomplete predicates ────────────────────────────────────────────────────
  const uniqPoliciesForGroup = (g: Group) =>
    new Set(g.bindings.map(b => b.policyId).filter(Boolean)).size;

  const isGroupIncomplete    = (g: Group) => {
    // "Default group with all users" is a special Dynatrace group — never considered incomplete
    if (g.federationType === "ALL_USERS" || g.name === "Default group with all users") return false;
    // Role-based (classic) groups don't use policies — not considered incomplete
    if (Object.keys(g.accessRight ?? {}).length > 0) return false;
    return g.userCount === 0 || uniqPoliciesForGroup(g) === 0;
  };
  // Global (Dynatrace-managed) policies are never flagged as incomplete
  const isPolicyIncomplete   = (p: Policy)   => p.levelType !== "global" && ((policyToGroupIds.get(p.id)?.size ?? 0) === 0 || !p.statementQuery);
  const isBoundaryIncomplete = (b: Boundary) => (boundaryToGroupCount.get(b.id) ?? 0) === 0;

  // ── Filtered & sorted collections ────────────────────────────────────────────
  const filteredGroups = groups
    .filter((g) => {
      if (!matches(g, searchG)) return false;
      if (userGroupIds && !userGroupIds.has(g.id)) return false;
      if (filterIncompleteG && !isGroupIncomplete(g)) return false;
      // Level filter: multi-select — empty = all; keys: "account" | envId
      if (levelFilters.size > 0) {
        const matchesLevel = g.bindings.some(b => {
          if (levelFilters.has("account") && b.levelType === "account") return true;
          if (b.levelType === "environment" && levelFilters.has(b.levelId)) return true;
          return false;
        });
        if (!matchesLevel) return false;
      }
      return true;
    })
    .sort((a, b) => {
      if (preserveGroupOrder) {
        const aIndex = groupOrderRef.current.indexOf(a.id);
        const bIndex = groupOrderRef.current.indexOf(b.id);
        if (aIndex >= 0 && bIndex >= 0) return aIndex - bIndex;
      }
      if (sortG === "users")    return b.userCount - a.userCount;
      if (sortG === "policies") return uniqPoliciesForGroup(b) - uniqPoliciesForGroup(a);
      // default: selection-aware — put related groups at top when policy/boundary selected
      if (!selectedPolicy && !selectedBoundary) return 0;
      const aHl = selectedPolicy ? (policyToGroupIds.get(selectedPolicy.id)?.has(a.id) ?? false) : boundGroupIds.has(a.id);
      const bHl = selectedPolicy ? (policyToGroupIds.get(selectedPolicy.id)?.has(b.id) ?? false) : boundGroupIds.has(b.id);
      return aHl === bHl ? 0 : aHl ? -1 : 1;
    });

  useEffect(() => {
    if (selectedPolicy && !preserveGroupOrder) {
      groupOrderRef.current = filteredGroups.map((group) => group.id);
    }
  }, [filteredGroups, selectedPolicy, preserveGroupOrder]);

  const filteredPolicies = policies
    .filter((p) => {
      if (!matches(p, searchP)) return false;
      if (userPolicyIds && !userPolicyIds.has(p.id)) return false;
      if (filterIncompleteP && !isPolicyIncomplete(p)) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortP === "groups")     return (policyToGroupIds.get(b.id)?.size ?? 0) - (policyToGroupIds.get(a.id)?.size ?? 0);
      if (sortP === "boundaries") return (policyToBoundaryCount.get(b.id) ?? 0) - (policyToBoundaryCount.get(a.id) ?? 0);
      if (sortP === "dt") {
        const aD = a.levelType === "global" ? 1 : 0;
        const bD = b.levelType === "global" ? 1 : 0;
        return bD - aD;
      }
      // default: selection-aware — put related policies at top when group/boundary selected
      if (!selectedGroup && !selectedBoundary) return 0;
      return (boundPolicyIds.has(a.id) === boundPolicyIds.has(b.id)) ? 0 : boundPolicyIds.has(a.id) ? -1 : 1;
    });

  const filteredBoundaries = boundaries
    .filter((b) => {
      if (!matches(b, searchB)) return false;
      if (userBoundaryIds && !userBoundaryIds.has(b.id)) return false;
      if (filterIncompleteB && !isBoundaryIncomplete(b)) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortB === "groups")   return (boundaryToGroupCount.get(b.id) ?? 0) - (boundaryToGroupCount.get(a.id) ?? 0);
      if (sortB === "policies") return (boundaryToPolicyCount.get(b.id) ?? 0) - (boundaryToPolicyCount.get(a.id) ?? 0);
      // default: selection-aware — put related boundaries at top when group/policy selected
      if (!selectedGroup && !selectedPolicy && !selectedBoundary) return 0;
      return (boundBoundaryIds.has(a.id) === boundBoundaryIds.has(b.id)) ? 0 : boundBoundaryIds.has(a.id) ? -1 : 1;
    });

  // Warn counts (on base-filtered set, before incomplete filter)
  const warnCountG = groups
    .filter(g => matches(g, searchG) && (!userGroupIds || userGroupIds.has(g.id)) && isGroupIncomplete(g)).length;
  const warnCountP = policies
    .filter(p => matches(p, searchP) && (!userPolicyIds || userPolicyIds.has(p.id)) && isPolicyIncomplete(p)).length;
  const warnCountB = boundaries
    .filter(b => matches(b, searchB) && (!userBoundaryIds || userBoundaryIds.has(b.id)) && isBoundaryIncomplete(b)).length;

  // Compare-slot user filter cascades
  const compareUserPolicyIds = useMemo<Set<string> | null>(() => {
    if (!compareUserGroupIds || !compareData) return null;
    const ids = new Set<string>();
    for (const g of compareData.groups)
      if (compareUserGroupIds.has(g.id)) for (const b of g.bindings) if (b.policyId) ids.add(b.policyId);
    return ids;
  }, [compareUserGroupIds, compareData]);

  const compareUserBoundaryIds = useMemo<Set<string> | null>(() => {
    if (!compareUserGroupIds || !compareData) return null;
    const ids = new Set<string>();
    for (const g of compareData.groups)
      if (compareUserGroupIds.has(g.id)) for (const b of g.bindings) for (const bid of b.boundaryIds) ids.add(bid);
    return ids;
  }, [compareUserGroupIds, compareData]);

  const filteredCompareGroups = useMemo(() =>
    (compareData?.groups ?? []).filter(g => !compareUserGroupIds || compareUserGroupIds.has(g.id)),
    [compareData, compareUserGroupIds]);

  const filteredComparePolicies = useMemo(() =>
    (compareData?.policies ?? []).filter(p => !compareUserPolicyIds || compareUserPolicyIds.has(p.id)),
    [compareData, compareUserPolicyIds]);

  const filteredCompareBoundaries = useMemo(() =>
    (compareData?.boundaries ?? []).filter(b => !compareUserBoundaryIds || compareUserBoundaryIds.has(b.id)),
    [compareData, compareUserBoundaryIds]);

  function groupModified(cur: Group, orig: Group): boolean {
    if (cur.name !== orig.name) return true;
    const origIds = new Set(orig.bindings.map(b => b.policyId));
    const curIds  = new Set(cur.bindings.map(b => b.policyId));
    return origIds.size !== curIds.size || [...curIds].some(id => !origIds.has(id));
  }

  const diffGroups = useMemo<DiffEntry<Group>[]>(() => {
    if (!compareMode || !compareData) return [];
    const cmpMap = new Map(filteredCompareGroups.map(g => [g.id, g]));
    const curSet = new Set(filteredGroups.map(g => g.id));
    const result: DiffEntry<Group>[] = [];
    for (const g of filteredGroups) {
      const orig = cmpMap.get(g.id);
      result.push(!orig
        ? { status: 'added', item: g }
        : { status: groupModified(g, orig) ? 'modified' : 'unchanged', item: g, compare: orig });
    }
    for (const g of filteredCompareGroups)
      if (!curSet.has(g.id)) result.push({ status: 'removed', item: g });
    return result;
  }, [compareMode, compareData, filteredGroups, filteredCompareGroups]);

  const diffPolicies = useMemo<DiffEntry<Policy>[]>(() => {
    if (!compareMode || !compareData) return [];
    const cmpMap = new Map(filteredComparePolicies.map(p => [p.id, p]));
    const curSet = new Set(filteredPolicies.map(p => p.id));
    const result: DiffEntry<Policy>[] = [];
    for (const p of filteredPolicies) {
      const orig = cmpMap.get(p.id);
      result.push(!orig
        ? { status: 'added', item: p }
        : { status: (p.name !== orig.name || p.statementQuery !== orig.statementQuery) ? 'modified' : 'unchanged', item: p, compare: orig });
    }
    for (const p of filteredComparePolicies)
      if (!curSet.has(p.id)) result.push({ status: 'removed', item: p });
    return result;
  }, [compareMode, compareData, filteredPolicies, filteredComparePolicies]);

  const diffBoundaries = useMemo<DiffEntry<Boundary>[]>(() => {
    if (!compareMode || !compareData) return [];
    const cmpMap = new Map(filteredCompareBoundaries.map(b => [b.id, b]));
    const curSet = new Set(filteredBoundaries.map(b => b.id));
    const result: DiffEntry<Boundary>[] = [];
    for (const b of filteredBoundaries) {
      const orig = cmpMap.get(b.id);
      result.push(!orig
        ? { status: 'added', item: b }
        : { status: (b.name !== orig.name || b.query !== orig.query) ? 'modified' : 'unchanged', item: b, compare: orig });
    }
    for (const b of filteredCompareBoundaries)
      if (!curSet.has(b.id)) result.push({ status: 'removed', item: b });
    return result;
  }, [compareMode, compareData, filteredBoundaries, filteredCompareBoundaries]);

  function diffVisible(status: DiffStatus): boolean {
    if (filterDiffStatus && status !== filterDiffStatus) return false;
    if (hideUnchanged && status === 'unchanged') return false;
    return true;
  }
  const sortedDiffGroups     = useMemo(() => diffGroups.filter(e    => matches(e.item, searchG) && diffVisible(e.status)).sort((a, b) => DIFF_ORDER[a.status] - DIFF_ORDER[b.status]), [diffGroups, searchG, hideUnchanged, filterDiffStatus]);
  const sortedDiffPolicies   = useMemo(() => diffPolicies.filter(e  => matches(e.item, searchP) && diffVisible(e.status)).sort((a, b) => DIFF_ORDER[a.status] - DIFF_ORDER[b.status]), [diffPolicies, searchP, hideUnchanged, filterDiffStatus]);
  const sortedDiffBoundaries = useMemo(() => diffBoundaries.filter(e => matches(e.item, searchB) && diffVisible(e.status)).sort((a, b) => DIFF_ORDER[a.status] - DIFF_ORDER[b.status]), [diffBoundaries, searchB, hideUnchanged, filterDiffStatus]);

  function diffStats(entries: DiffEntry<unknown>[]) {
    return {
      added:    entries.filter(e => e.status === 'added').length,
      removed:  entries.filter(e => e.status === 'removed').length,
      modified: entries.filter(e => e.status === 'modified').length,
    };
  }

  const policyLevelMap: Record<string, string[]> = useMemo(() => {
    if (!selectedGroup) return {};
    const m: Record<string, string[]> = {};
    for (const b of selectedGroup.bindings) {
      if (!b.policyId) continue;
      if (!m[b.policyId]) m[b.policyId] = [];
      m[b.policyId].push(b.levelName || "Account");
    }
    return m;
  }, [selectedGroup]);

  const bindParamsEntries = useMemo(
    () => (selectedGroup?.bindings ?? []).filter((b) => Object.keys(b.bindParams ?? {}).length > 0),
    [selectedGroup],
  );

  // Build dropdown options from slotMeta (snapshot index + date + optional user email)
  const dropdownOptions = ALL_SLOTS
    .filter((s) => slotMeta[s])
    .map((s) => ({
      slot:  s,
      label: `📸 ${slotLabel(s)} — ${slotMeta[s]!.ts}${slotMeta[s]!.userEmail ? ` 👤 ${slotMeta[s]!.userEmail}` : ""}`,
    }));

  const compareDropdownOptions = ALL_SLOTS
    .filter(s => slotMeta[s] && s !== selectedSlot)
    .map(s => ({
      slot: s,
      label: `📸 ${slotLabel(s, true)} — ${slotMeta[s]!.ts}${slotMeta[s]!.userEmail ? ` 👤 ${slotMeta[s]!.userEmail}` : ""}`,
    }));

  const hasData    = groups.length > 0 || policies.length > 0 || boundaries.length > 0;
  const showDetails = !!(selectedGroup ?? selectedPolicy ?? selectedBoundary);
  const [aiAssistOpen, setAiAssistOpen] = useState(false);
  const fullPolicyContext = JSON.stringify({
    selectedGroup,
    policies,
    boundaries,
  }, null, 2);

  // ── Deep-link helpers — Dynatrace Account Management (myaccount.dynatrace.com) ─
  // URL format confirmed: /account/iam/group-management/{id}?account-uuid={accountId}
  // Policies and boundaries do not have a direct deep-link URL available.
  function groupLink(id: string) {
    if (!accountId) return null;
    return `https://myaccount.dynatrace.com/account/iam/group-management/${id}?account-uuid=${accountId}`;
  }

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div className="sankey-root">

      {/* ── Toolbar ────────────────────────────────────────────────────────────── */}
      <div className="sankey-toolbar">
        <span className="sankey-title">IAM Sankey</span>

        {dropdownOptions.length > 0 && (
          <select
            className="sankey-select"
            value={selectedSlot}
            onChange={(e) => {
              const val = e.target.value;
              if (val === "no-filter") { clearUserFilter(); return; }
              const slot = val as Slot;
              setSelectedSlot(slot);
              const slotUser = slotMeta[slot]?.userEmail ?? "";
              setFilterEmail(slotUser);
              setFilterEmailInput(slotUser);
              saveUserFilter({ key: USER_FILTER_KEY, body: { value: JSON.stringify({ filterEmail: slotUser }) } });
              if (!slotUser) setUserGroupIds(null);
            }}
            disabled={isLoading || refreshStatus === "running"}
            title="Choose snapshot / user"
          >
            {dropdownOptions.map((o) => (
              <option key={o.slot} value={o.slot}>{o.label}</option>
            ))}
            {filterEmail && (
              <option value="no-filter">— (no user filter)</option>
            )}
          </select>
        )}

        {compareMode && (
          <>
            <span className="sankey-compare-sep">⇄</span>
            <select
              className="sankey-select"
              value={compareSlot}
              onChange={(e) => setCompareSlot(e.target.value as Slot)}
              disabled={isLoading}
              title="Comparison snapshot"
            >
              {compareDropdownOptions.map((o) => (
                <option key={o.slot} value={o.slot}>{o.label}</option>
              ))}
            </select>
          </>
        )}

        <button
          className={`sankey-btn sankey-btn-compare${compareMode ? " active" : ""}`}
          onClick={() => {
            if (compareMode) {
              setCompareMode(false);
              setCompareData(null);
              setCompareUserGroupIds(null);
              setFilterDiffStatus(null);
              setHideUnchanged(false);
            } else {
              setCompareMode(true);
              // default compareSlot = first slot that is not selectedSlot
              const avail = ALL_SLOTS.filter(s => slotMeta[s] && s !== selectedSlot);
              if (avail.length > 0) setCompareSlot(avail[0]);
            }
          }}
          disabled={!compareMode && compareDropdownOptions.length === 0}
          title={compareMode ? "Exit compare mode" : "Compare two snapshots"}
        >
          {compareMode ? "✕ Compare" : "⇄ Compare"}
        </button>

        <button
          className={`sankey-btn sankey-btn-refresh${refreshStatus === "running" ? " running" : ""}`}
          onClick={() => void triggerRefresh()}
          disabled={refreshStatus === "running" || isLoading}
          title={workflowId ? "Collect IAM data" : `Workflow "${WORKFLOW_TITLE}" not found`}
        >
          {refreshStatus === "running" ? "⟳ Running…" : isLoading ? "⟳ Loading…" : "📸 New Snapshot"}
        </button>

        <button
          className={`sankey-btn sankey-btn-settings${credsOk ? " configured" : " unconfigured"}`}
          onClick={() => { setShowSettings((v) => !v); setSaveStatus("idle"); setSaveError(""); }}
          title={credsOk ? `Vault: ${vaultId}` : "Configure credentials"}
        >
          ⚙ {credsOk ? "Credentials ✓" : "Credentials ✗"}
        </button>

        {accountId && (
          <a
            className="sankey-btn sankey-btn-myaccount"
            href={`https://myaccount.dynatrace.com/account/home?account-uuid=${accountId}`}
            target="_blank"
            rel="noopener noreferrer"
            title={`Open My Account (${accountId})`}
          >
            ↗ My Account
          </a>
        )}

        {/* ── Back button — undo last selection ── */}
        {selectionHistory.length > 0 && (
          <button
            className="sankey-btn sankey-btn-back"
            onClick={goBack}
            title="Go back to previous selection"
          >
            ← Back
          </button>
        )}

        {/* ── Clear filters button ── */}
        {(selectedGroup || selectedPolicy || selectedBoundary || searchG || searchP || searchB || 
          filterIncompleteG || filterIncompleteP || filterIncompleteB || filterEmail || levelFilters.size > 0) && (
          <button
            className="sankey-btn sankey-btn-clear"
            onClick={clearAllFilters}
            title="Reset all filters and selections"
          >
            ✕ Clear Filters
          </button>
        )}

        {/* ── User filter — email input, ↵ validate (= Refresh), × to clear ── */}
        <div className="sankey-user-filter">
          <span className="sankey-user-filter-label">👤</span>
          <input
            type="email"
            className={`sankey-email-input${filterEmail ? " has-value" : ""}`}
            placeholder="user@domain.com"
            value={filterEmailInput}
            onChange={(e) => setFilterEmailInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void triggerRefresh(); }}
            onBlur={applyUserFilter}
            disabled={isLoading || refreshStatus === "running"}
            title="Enter email + ↵ or ✓ to refresh with this user filter"
          />
          {filterEmailInput && (
            <button
              className="sankey-btn-icon-validate"
              onClick={() => void triggerRefresh()}
              disabled={isLoading || refreshStatus === "running"}
              title="Apply and refresh with this user filter"
            >✓</button>
          )}
          {filterEmailInput && (
            <button className="sankey-btn-icon-clear" onClick={clearUserFilter}
              title="Clear user filter">×</button>
          )}
          {/* Environment scope multi-select dropdown — same line as user filter */}
          {!compareMode && (iamData?.environments?.length ?? 0) > 0 && (() => {
            const envs = iamData?.environments ?? [];
            const selCount = levelFilters.size;
            const label = selCount === 0
              ? "🌐 All environments"
              : selCount === 1
                ? (levelFilters.has("account")
                    ? "☁ Account"
                    : `📦 ${envs.find(e => levelFilters.has(e.id))?.name ?? "1 env"}`)
                : `${selCount} environments`;
            return (
              <>
                <span className="sankey-user-filter-sep">|</span>
                <div ref={levelFilterRef} className="level-filter-dropdown">
                  <button
                    className={`level-filter-trigger${selCount > 0 ? " has-selection" : ""}`}
                    onClick={() => {
                      if (!levelFilterOpen && levelFilterRef.current) {
                        const r = levelFilterRef.current.getBoundingClientRect();
                        setLevelPanelPos({ top: r.bottom + 4, left: r.left });
                      }
                      setLevelFilterOpen(v => !v);
                    }}
                    title="Filter groups by environment scope"
                  >{label} ▾</button>
                </div>
                {levelFilterOpen && createPortal(
                  <div ref={levelPanelRef} className="level-filter-panel"
                       style={{ top: levelPanelPos.top, left: levelPanelPos.left }}>
                    <label className="level-filter-item">
                      <input type="checkbox" checked={levelFilters.has("account")}
                        onChange={() => toggleLevelFilter("account")} />
                      <span>☁ Account</span>
                    </label>
                    {envs.map(env => (
                      <label key={env.id} className="level-filter-item">
                        <input type="checkbox" checked={levelFilters.has(env.id)}
                          onChange={() => toggleLevelFilter(env.id)} />
                        <span>📦 {env.name}</span>
                      </label>
                    ))}
                  </div>,
                  document.body
                )}
              </>
            );
          })()}
        </div>

        {filterEmail && userGroupIds && (
          <span className="sankey-filter-badge active"
            title={`${userGroupIds.size} groups for ${filterEmail}`}>
            👤 {userGroupIds.size}g
          </span>
        )}

        {statusMsg && (
          <span className={`sankey-status${refreshStatus === "error" ? " error" : ""}`}>{statusMsg}</span>
        )}

        {hasData && (
          <span className="sankey-summary">
            {userGroupIds
              ? `${filteredGroups.length}/${groups.length} groups · ${filteredPolicies.length}/${policies.length} policies · ${filteredBoundaries.length}/${boundaries.length} boundaries`
              : `${groups.length} groups · ${policies.length} policies · ${boundaries.length} boundaries`}
          </span>
        )}
      </div>

      {/* ── Diff legend ──────────────────────────────────────────────────────────── */}
      {compareMode && compareData && (
        <div className="sankey-diff-legend">
          <span className="diff-legend-item diff-added">＋ Added</span>
          <span className="diff-legend-item diff-modified">～ Modified</span>
          <span className="diff-legend-item diff-removed">－ Removed</span>
          <span className="diff-legend-item diff-unchanged">＝ Same</span>
          <span className="diff-legend-divider" />
          {(() => {
            const gs = diffStats(diffGroups);
            const ps = diffStats(diffPolicies);
            const bs = diffStats(diffBoundaries);
            const a = gs.added   + ps.added   + bs.added;
            const r = gs.removed + ps.removed + bs.removed;
            const m = gs.modified + ps.modified + bs.modified;
            const u = (diffGroups.length - gs.added - gs.removed - gs.modified)
                    + (diffPolicies.length - ps.added - ps.removed - ps.modified)
                    + (diffBoundaries.length - bs.added - bs.removed - bs.modified);
            const toggle = (s: DiffStatus) => setFilterDiffStatus(f => f === s ? null : s);
            return (
              <>
                {a > 0 && <span className={`diff-count diff-added clickable${filterDiffStatus === 'added' ? ' selected' : ''}`} onClick={() => toggle('added')} title="Filter by Added">+{a}</span>}
                {r > 0 && <span className={`diff-count diff-removed clickable${filterDiffStatus === 'removed' ? ' selected' : ''}`} onClick={() => toggle('removed')} title="Filter by Removed">−{r}</span>}
                {m > 0 && <span className={`diff-count diff-modified clickable${filterDiffStatus === 'modified' ? ' selected' : ''}`} onClick={() => toggle('modified')} title="Filter by Modified">~{m}</span>}
                {u > 0 && <span className={`diff-count diff-unchanged clickable${filterDiffStatus === 'unchanged' ? ' selected' : ''}`} onClick={() => toggle('unchanged')} title="Filter by Same">={u}</span>}
              </>
            );
          })()}
          <span className="diff-legend-divider" />
          <label className="diff-legend-toggle" title="Hide items identical in both snapshots">
            <input type="checkbox" checked={hideUnchanged} onChange={(e) => setHideUnchanged(e.target.checked)} />
            {" Hide same"}
          </label>
          <span className="diff-legend-slots">
            {"compare "}
            <strong>{selectedSlot}</strong>
            {slotMeta[selectedSlot]?.userEmail
              ? <span> 👤 {slotMeta[selectedSlot]!.userEmail}</span>
              : <span className="diff-no-user"> (no user)</span>}
            {" to "}
            <strong>{compareSlot}</strong>
            {slotMeta[compareSlot]?.userEmail
              ? <span> 👤 {slotMeta[compareSlot]!.userEmail}</span>
              : <span className="diff-no-user"> (no user)</span>}
          </span>
        </div>
      )}

      {/* ── Settings panel ─────────────────────────────────────────────────────── */}
      {showSettings && (
        <div className="sankey-settings">

          {/* ── Section 1: Link an existing vault ───────────────────────────────── */}
          <div className="sankey-settings-section-title">🔗 Link an existing vault</div>
          <div className="sankey-settings-row">
            <label className="sankey-settings-label">Vault</label>
            {vaultSearchStatus === "searching" && (
              <span className="sankey-settings-hint">Searching…</span>
            )}
            {vaultSearchStatus === "error" && (
              <span className="sankey-save-error">Search error.</span>
            )}
            {(vaultSearchStatus === "done") && (
              existingVaults.length > 0 ? (
                <select
                  className="sankey-settings-select"
                  value={selectedExistingVaultId}
                  onChange={(e) => {
                    const id = e.target.value;
                    setSelectedExistingVaultId(id);
                    const vault = existingVaults.find(v => v.id === id);
                    if (vault?.accountUuid) setAccountIdInput(vault.accountUuid);
                  }}
                >
                  {existingVaults.map((v) => (
                    <option key={v.id} value={v.id}>
                      {v.name}{v.accountUuid ? ` — ${v.accountUuid.slice(0, 8)}…` : ` (${v.id.slice(0, 8)}…)`}
                    </option>
                  ))}
                </select>
              ) : (
                <span className="sankey-settings-hint">No vault found (prefix: {VAULT_NAME_PREFIX}*)</span>
              )
            )}
          </div>
          {vaultSearchStatus === "done" && existingVaults.length > 0 && (
            <>
              <div className="sankey-settings-row">
                <label className="sankey-settings-label">Account ID</label>
                <input className="sankey-settings-input" value={accountIdInput}
                       onChange={(e) => setAccountIdInput(e.target.value)}
                       placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" spellCheck={false} />
              </div>
              <div className="sankey-settings-actions">
                <button className="sankey-btn" onClick={() => void handleLinkVault()}
                        disabled={!selectedExistingVaultId || !accountIdInput.trim()}>
                  🔗 Link this vault
                </button>
              </div>
            </>
          )}

          {/* ── Divider ─────────────────────────────────────────────────────────── */}
          <div className="sankey-settings-divider" />

          {/* ── Section 2: Create / update a vault ──────────────────────────────── */}
          <div className="sankey-settings-section-title">➕ Create / update vault</div>
          <div className="sankey-settings-row">
            <label className="sankey-settings-label">Account ID</label>
            <input className="sankey-settings-input" value={accountIdInput}
                   onChange={(e) => setAccountIdInput(e.target.value)}
                   placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" spellCheck={false} />
          </div>
          <div className="sankey-settings-row">
            <label className="sankey-settings-label">Client ID</label>
            <input className="sankey-settings-input" value={clientIdInput}
                   onChange={(e) => setClientIdInput(e.target.value)}
                   placeholder="dt0s02.XXXXXXXX" spellCheck={false} />
          </div>
          <div className="sankey-settings-row">
            <label className="sankey-settings-label">Client Secret</label>
            <input className="sankey-settings-input" type="password" value={clientSecretInput}
                   onChange={(e) => setClientSecretInput(e.target.value)}
                   placeholder="dt0s02.XXXXXXXX…" spellCheck={false} />
          </div>
          {vaultId && (
            <div className="sankey-settings-row">
              <label className="sankey-settings-label">Current vault</label>
              <span className="sankey-settings-vaultid">{vaultId}</span>
            </div>
          )}
          {saveError && <span className="sankey-save-error">{saveError}</span>}
          <div className="sankey-settings-actions">
            <button className="sankey-btn" onClick={() => void handleSaveCreds()}
                    disabled={saveStatus === "saving"}>
              {saveStatus === "saving" ? "Saving…" : "💾 Save to Vault"}
            </button>
            <button className="sankey-btn sankey-btn-ghost" onClick={() => setShowSettings(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* ── 3-column graph ─────────────────────────────────────────────────────── */}
      <div className="sankey-graph" ref={graphRef}
           style={showDetails ? { flex: "1 1 0", minHeight: 0 } : { flex: 1 }}>

        <svg className="sankey-arrows" width={svgW} height={svgH} viewBox={`0 0 ${svgW} ${svgH}`}
             style={{ pointerEvents: "none" }}>
          <defs>
            <marker id="ah-teal" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 1.5 L 8.5 5 L 0 8.5 z" fill="#00b4d8" />
            </marker>
            <marker id="ah-purple" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 1.5 L 8.5 5 L 0 8.5 z" fill="#7b2fbe" />
            </marker>
          </defs>
          {svgPaths.map((p, i) => (
            <path key={i} d={p.d} stroke={p.color} strokeWidth={2} fill="none" opacity={0.72}
                  markerEnd={`url(#${p.markerId})`} />
          ))}
        </svg>

        {/* Groups */}
        <EntityColumn title="Groups"
          count={compareMode ? sortedDiffGroups.length : groups.length}
          diffBadge={compareMode ? (() => { const s = diffStats(diffGroups); const parts: string[] = []; if (s.added) parts.push(`+${s.added}`); if (s.removed) parts.push(`−${s.removed}`); if (s.modified) parts.push(`~${s.modified}`); return parts.join(' '); })() : undefined}
          warnCount={compareMode ? undefined : warnCountG}
          filterIncomplete={filterIncompleteG}
          onFilterIncomplete={() => setFilterIncompleteG(v => !v)}
          sortOptions={compareMode || selectedPolicy || selectedBoundary ? undefined : [
            { key: "users", label: "👥 Users" },
            { key: "policies", label: "◈ Policies" },
          ]}
          sortBy={sortG} onSort={(k) => setSortG(k as SortG)}
          search={searchG} onSearch={setSearchG} listRef={listGRef} onScroll={bumpScroll}>
          {compareMode
            ? sortedDiffGroups.map((entry) => {
                const g = entry.item;
                const hasBP = g.bindings.some((b) => Object.keys(b.bindParams ?? {}).length > 0);
                return (
                  <li key={g.id + entry.status} data-id={g.id}
                      className={`diff-${entry.status}`}
                      onClick={() => selectGroup(g)}>
                    <div className="entity-name-row">
                      <span className={`diff-badge diff-${entry.status}`}>
                        {entry.status === 'added' ? '+' : entry.status === 'removed' ? '−' : entry.status === 'modified' ? '~' : '='}
                      </span>
                      <span className="entity-name">{g.name || g.id || "(unnamed)"}</span>
                      {hasBP && <span className="bind-param-badge">{"{…}"}</span>}
                    </div>
                    {g.id && g.name && g.id !== g.name && <span className="entity-id">{g.id}</span>}
                  </li>
                );
              })
            : filteredGroups.map((g) => {
                const sel = selectedGroup?.id === g.id;
                const hl  = !sel && (selectedPolicy ? (policyToGroupIds.get(selectedPolicy.id)?.has(g.id) ?? false)
                                   : selectedBoundary ? boundGroupIds.has(g.id) : false);
                const dim = !sel && !hl && (selectedPolicy ?? selectedBoundary) !== null;
                const hasBP = g.bindings.some((b) => Object.keys(b.bindParams ?? {}).length > 0);
                const uniqPolicies = new Set(g.bindings.map(b => b.policyId).filter(Boolean)).size;
                const noUsers    = g.userCount === 0;
                const noPolicies = uniqPolicies === 0;
                const isWarn      = isGroupIncomplete(g);
                const link        = groupLink(g.id);
                const isAllUsers  = g.federationType === "ALL_USERS" || g.name === "Default group with all users";
                const isRoleBased = Object.keys(g.accessRight ?? {}).length > 0;
                const environments = iamData?.environments ?? [];
                const hasAccountBinding = g.bindings.some(b => b.levelType === "account");
                const groupEnvIds = [...new Set(
                  g.bindings.filter(b => b.levelType === "environment" && b.levelId).map(b => b.levelId)
                )];
                const isEnvExpanded = expandedEnvGroups.has(g.id);
                return (
                  <li key={g.id} data-id={g.id}
                      className={[sel ? "selected" : "", hl ? "highlighted" : "", dim ? "dimmed" : "", isRoleBased && !sel && !hl ? "entity-roles" : "", isAllUsers && !sel && !hl ? "entity-allusers" : "", isWarn ? "entity-warn" : ""].filter(Boolean).join(" ")}
                      onClick={() => selectGroup(g)}>
                    <div className="entity-name-row">
                      <span className="entity-name">{g.name || g.id || "(unnamed)"}</span>
                      {isRoleBased && (
                        <span className="badge-roles" title="Classic role-based access (no policy binding)">⚡ Roles</span>
                      )}
                      {g.userCount >= 0 && (
                        <span className={`badge-users${g.userCount === 0 ? " badge-zero" : ""}`}
                              title={`${g.userCount} user${g.userCount !== 1 ? "s" : ""}`}>
                          👥 {g.userCount}
                        </span>
                      )}
                      <span className={`badge-policies${uniqPolicies === 0 ? " badge-zero" : ""}`}
                            title={`${uniqPolicies} polic${uniqPolicies !== 1 ? "ies" : "y"}`}>
                        ◈ {uniqPolicies}
                      </span>
                      {hasBP && <span className="bind-param-badge" title="Has bind parameters">{"{…}"}</span>}
                      {/* Binding scope indicators: account and/or environments */}
                      {hasAccountBinding && (
                        <span className="level-note" title="Account-level (applies to all environments)">• account</span>
                      )}
                      {!hasAccountBinding && groupEnvIds.length === 1 && (
                        <span className="level-note" title={groupEnvIds[0]}>
                          • {environments.find(e => e.id === groupEnvIds[0])?.name ?? groupEnvIds[0]}
                        </span>
                      )}
                      {!hasAccountBinding && groupEnvIds.length > 1 && (
                        isEnvExpanded ? (
                          <span className="level-env-tags" onClick={(e) => {
                            e.stopPropagation();
                            setExpandedEnvGroups(prev => { const s = new Set(prev); s.delete(g.id); return s; });
                          }}>
                            {groupEnvIds.map(id => (
                              <span key={id} className="level-env-tag">
                                {environments.find(e => e.id === id)?.name ?? id}
                              </span>
                            ))}
                          </span>
                        ) : (
                          <button
                            className="level-env-count"
                            onClick={(e) => {
                              e.stopPropagation();
                              setExpandedEnvGroups(prev => { const s = new Set(prev); s.add(g.id); return s; });
                            }}
                            title={groupEnvIds.map(id => environments.find(e => e.id === id)?.name ?? id).join(', ')}
                          >+{groupEnvIds.length}</button>
                        )
                      )}
                      {link && (
                        <a href={link} target="_blank" rel="noopener noreferrer"
                           className="entity-deeplink"
                           title="Edit | Groups | Identity & access management | Account Management"
                           onClick={(e) => e.stopPropagation()}>↗</a>
                      )}
                    </div>
                    {g.id && g.name && g.id !== g.name && <span className="entity-id">{g.id}</span>}
                  </li>
                );
              })
          }
        </EntityColumn>

        {/* Policies */}
        <EntityColumn title="Policies"
          count={compareMode ? sortedDiffPolicies.length : policies.length}
          diffBadge={compareMode ? (() => { const s = diffStats(diffPolicies); const parts: string[] = []; if (s.added) parts.push(`+${s.added}`); if (s.removed) parts.push(`−${s.removed}`); if (s.modified) parts.push(`~${s.modified}`); return parts.join(' '); })() : undefined}
          warnCount={compareMode ? undefined : warnCountP}
          filterIncomplete={filterIncompleteP}
          onFilterIncomplete={() => setFilterIncompleteP(v => !v)}
          sortOptions={compareMode || selectedGroup || selectedBoundary ? undefined : [
            { key: "groups", label: "👥 Groups" },
            { key: "boundaries", label: "🔒 Boundaries" },
            { key: "dt", label: "DT", className: "dt-sort" },
          ]}
          sortBy={sortP} onSort={(k) => setSortP(k as SortP)}
          search={searchP} onSearch={setSearchP} listRef={listPRef} onScroll={bumpScroll}>
          {compareMode
            ? sortedDiffPolicies.map((entry) => {
                const p = entry.item;
                return (
                  <li key={p.id + entry.status} data-id={p.id}
                      className={`diff-${entry.status}`}
                      onClick={() => selectPolicy(p)}>
                    <div className="entity-name-row">
                      <span className={`diff-badge diff-${entry.status}`}>
                        {entry.status === 'added' ? '+' : entry.status === 'removed' ? '−' : entry.status === 'modified' ? '~' : '='}
                      </span>
                      <span className="entity-name">{p.name || p.id || "(unnamed)"}</span>
                    </div>
                    {p.id && p.name && p.id !== p.name && <span className="entity-id">{p.id}</span>}
                  </li>
                );
              })
            : filteredPolicies.map((p) => {
                const sel    = selectedPolicy?.id === p.id;
                const hl     = !sel && !!(selectedGroup ? boundPolicyIds.has(p.id) : selectedBoundary ? boundPolicyIds.has(p.id) : false);
                const dim    = !sel && !hl && (selectedGroup ?? selectedPolicy ?? selectedBoundary) !== null;
                const levels = selectedGroup ? (policyLevelMap[p.id] ?? []) : [];
                const showTags = levels.length > 1 || (levels.length === 1 && levels[0] !== "Account");
                const grpCount = policyToGroupIds.get(p.id)?.size ?? 0;
                const bndCount = policyToBoundaryCount.get(p.id) ?? 0;
                const isWarn   = grpCount === 0 && p.levelType !== "global";
                return (
                  <li key={p.id} data-id={p.id}
                      className={[sel ? "selected" : "", hl ? "highlighted" : "", dim ? "dimmed" : "", isWarn ? "entity-warn" : ""].filter(Boolean).join(" ")}
                      onClick={() => selectPolicy(p)}>
                    <div className="entity-name-row">
                      <span className={`entity-name${p.levelType === "global" ? " entity-name-dt" : ""}`}>{p.name || p.id || "(unnamed)"}</span>
                      {p.levelType === "global" && (
                        <span className="badge-dt" title="Dynatrace policy (global level)">DT</span>
                      )}
                      <span className={`badge-groups${grpCount === 0 ? " badge-zero" : ""}`}
                            title={`${grpCount} group${grpCount !== 1 ? "s" : ""}`}>
                        👥 {grpCount}
                      </span>
                      {bndCount > 0 && (
                        <span className="badge-boundaries" title={`${bndCount} boundar${bndCount !== 1 ? "ies" : "y"}`}>
                          🔒 {bndCount}
                        </span>
                      )}
                    </div>
                    {p.id && p.name && p.id !== p.name && <span className="entity-id">{p.id}</span>}
                    {showTags && <div className="env-tags">{levels.map((lvl) => <span key={lvl} className="env-tag">{lvl}</span>)}</div>}
                  </li>
                );
              })
          }
        </EntityColumn>

        {/* Boundaries */}
        <EntityColumn title="Boundaries"
          count={compareMode ? sortedDiffBoundaries.length : boundaries.length}
          diffBadge={compareMode ? (() => { const s = diffStats(diffBoundaries); const parts: string[] = []; if (s.added) parts.push(`+${s.added}`); if (s.removed) parts.push(`−${s.removed}`); if (s.modified) parts.push(`~${s.modified}`); return parts.join(' '); })() : undefined}
          warnCount={compareMode ? undefined : warnCountB}
          filterIncomplete={filterIncompleteB}
          onFilterIncomplete={() => setFilterIncompleteB(v => !v)}
          sortOptions={compareMode || selectedGroup || selectedPolicy ? undefined : [
            { key: "groups", label: "👥 Groups" },
            { key: "policies", label: "◈ Policies" }
          ]}
          sortBy={sortB} onSort={(k) => setSortB(k as SortB)}
          search={searchB} onSearch={setSearchB} listRef={listBRef} onScroll={bumpScroll}>
          {compareMode
            ? sortedDiffBoundaries.map((entry) => {
                const b = entry.item;
                return (
                  <li key={b.id + entry.status} data-id={b.id}
                      className={`diff-${entry.status}`}
                      onClick={() => selectBoundary(b)}>
                    <div className="entity-name-row">
                      <span className={`diff-badge diff-${entry.status}`}>
                        {entry.status === 'added' ? '+' : entry.status === 'removed' ? '−' : entry.status === 'modified' ? '~' : '='}
                      </span>
                      <span className="entity-name">{b.name || b.id || "(unnamed)"}</span>
                    </div>
                    {b.id && b.name && b.id !== b.name && <span className="entity-id">{b.id}</span>}
                  </li>
                );
              })
            : filteredBoundaries.map((b) => {
                const sel      = selectedBoundary?.id === b.id;
                const hl       = !sel && !!((selectedGroup || selectedPolicy) ? boundBoundaryIds.has(b.id) : false);
                const dim      = !sel && !hl && (selectedGroup ?? selectedPolicy ?? selectedBoundary) !== null;
                const grpCount = boundaryToGroupCount.get(b.id) ?? 0;
                const polCount = boundaryToPolicyCount.get(b.id) ?? 0;
                const isWarn   = grpCount === 0;
                return (
                  <li key={b.id} data-id={b.id}
                      className={[sel ? "selected" : "", hl ? "highlighted" : "", dim ? "dimmed" : "", isWarn ? "entity-warn" : ""].filter(Boolean).join(" ")}
                      onClick={() => selectBoundary(b)}>
                    <div className="entity-name-row">
                      <span className="entity-name">{b.name || b.id || "(unnamed)"}</span>
                      <span className={`badge-groups${grpCount === 0 ? " badge-zero" : ""}`}
                            title={`${grpCount} group${grpCount !== 1 ? "s" : ""}`}>
                        👥 {grpCount}
                      </span>
                      {polCount > 0 && (
                        <span className="badge-policies" title={`${polCount} polic${polCount !== 1 ? "ies" : "y"}`}>
                          ◈ {polCount}
                        </span>
                      )}
                    </div>
                    {b.id && b.name && b.id !== b.name && <span className="entity-id">{b.id}</span>}
                  </li>
                );
              })
          }
        </EntityColumn>

        {/* Empty states */}
        {!hasData && !credsOk && (
          <div className="sankey-empty"><p>Click ⚙ to configure credentials, then 📸 New Snapshot.</p></div>
        )}
        {!hasData && credsOk && !workflowId && (
          <div className="sankey-empty">
            <p>Import <code>workflow/iam-data-collector.workflow.json</code> into Dynatrace Automations,<br />then click ⟳ Refresh.</p>
          </div>
        )}
        {!hasData && credsOk && !!workflowId && !isLoading && (
          <div className="sankey-empty"><p>No data. Click 📸 New Snapshot to collect IAM data.</p></div>
        )}
        {!hasData && isLoading && (
          <div className="sankey-empty"><p>Loading…</p></div>
        )}
      </div>

      {/* ── Details panel ──────────────────────────────────────────────────────── */}
      {showDetails && (
        <>
          <div className="sankey-details-handle" onMouseDown={onHandleMouseDown} title="Drag to resize" />
          <div className="sankey-details" style={{ height: detailsH }}>
            {/* Priority: policy > group > boundary — avoids double-render when group+policy coexist */}
            {selectedPolicy
              ? <EntityDetails title="Policy"   entity={selectedPolicy}   extraText={selectedPolicy.statementQuery} fullPolicy={fullPolicyContext} />
              : selectedGroup
              ? <GroupCompilation group={selectedGroup} policies={policies} boundaries={boundaries} environments={iamData?.environments ?? []} fullPolicy={fullPolicyContext} />
              : selectedBoundary
              ? <EntityDetails title="Boundary" entity={selectedBoundary} extraText={selectedBoundary.query} />
              : null}
          </div>
        </>
      )}
      {AI_FEATURES_ENABLED && <button className="ai-assist-toggle" onClick={() => setAiAssistOpen((open) => !open)} aria-expanded={aiAssistOpen}>
        AI Assist
      </button>}
      {AI_FEATURES_ENABLED && aiAssistOpen && (
        <div className="ai-assist-popover">
          <AiAssistPanel
            fullPolicy={fullPolicyContext}
            groupName={selectedGroup?.name || selectedGroup?.id || "All groups"}
            environments={(iamData?.environments ?? []).map((e) => e.name || e.id).join(", ")}
            onClose={() => setAiAssistOpen(false)}
          />
        </div>
      )}
    </div>
  );
}

// ── EntityColumn ──────────────────────────────────────────────────────────────

interface SortOption { key: string; label: string; className?: string; }

interface EntityColumnProps {
  title: string;
  count: number;
  diffBadge?: string;
  search: string;
  onSearch: (v: string) => void;
  listRef: React.Ref<HTMLUListElement>;
  onScroll: () => void;
  children: React.ReactNode;
  // incomplete filter
  warnCount?: number;
  filterIncomplete?: boolean;
  onFilterIncomplete?: () => void;
  // sort
  sortOptions?: SortOption[];
  sortBy?: string;
  onSort?: (key: string) => void;
}
function EntityColumn({
  title, count, diffBadge, search, onSearch, listRef, onScroll, children,
  warnCount, filterIncomplete, onFilterIncomplete,
  sortOptions, sortBy, onSort,
}: EntityColumnProps) {
  return (
    <div className="sankey-col">
      <div className="col-header">
        <span className="col-title">{title}</span>
        <span className="col-count">{count}</span>
        {warnCount !== undefined && warnCount > 0 && onFilterIncomplete && (
          <button
            className={`col-warn-filter${filterIncomplete ? " active" : ""}`}
            onClick={onFilterIncomplete}
            title={filterIncomplete ? "Show all" : `Show incomplete (${warnCount})`}
          >⚠ {warnCount}</button>
        )}
        {diffBadge && <span className="col-diff-badge">{diffBadge}</span>}
      </div>
      <div className="col-search-wrap">
        <input className="col-search" placeholder={`Search ${title.toLowerCase()}…`}
               value={search} onChange={(e) => onSearch(e.target.value)} spellCheck={false} />
        {search && <button className="col-search-clear" onClick={() => onSearch("")} title="Clear">×</button>}
      </div>
      {sortOptions && sortOptions.length > 0 && onSort && (
        <div className="col-sort-bar">
          <span className="col-sort-label">↕</span>
          {sortOptions.map(o => (
            <button key={o.key}
              className={`col-sort-btn${o.className ? ` ${o.className}` : ""}${sortBy === o.key ? " active" : ""}`}
              onClick={() => onSort(o.key === sortBy ? "default" : o.key)}
            >{o.label}</button>
          ))}
        </div>
      )}
      <ul ref={listRef} className="entity-list" onScroll={onScroll}>{children}</ul>
    </div>
  );
}

// ── Statement parser ─────────────────────────────────────────────────────────

interface ParsedStatement { effect: string; actions: string[]; condition?: string; }

function parseStatementQuery(sq: string): ParsedStatement[] {
  const out: ParsedStatement[] = [];
  if (!sq?.trim()) return out;
  let cur: ParsedStatement | null = null;
  for (const raw of sq.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const m = line.match(/^(ALLOW|DENY)\s+(.+)/i);
    if (m) {
      if (cur) out.push(cur);
      const effect = m[1].toUpperCase();
      const rest   = m[2].trim();
      const wi     = rest.toUpperCase().indexOf(" WHERE ");
      cur = wi >= 0
        ? { effect, actions: rest.slice(0, wi).split(",").map(a => a.trim()).filter(Boolean), condition: rest.slice(wi + 7).trim() }
        : { effect, actions: rest.split(",").map(a => a.trim()).filter(Boolean) };
    } else if (/^WHERE\s+/i.test(line) && cur) {
      cur.condition = line.replace(/^WHERE\s+/i, "").trim();
    }
  }
  if (cur) out.push(cur);
  return out;
}

function aiBadgeClass(text: string): string {
  if (/(security|risk|dangerous|too broad|critical)/i.test(text)) return "ai-badge-danger";
  if (/(warning|redund|missing|restriction)/i.test(text)) return "ai-badge-warning";
  return "ai-badge-info";
}

function AiExplainRule({ fullPolicy, currentRule }: { fullPolicy: string; currentRule: string }) {
  const [open, setOpen] = useState(false);
  const { data, error, isLoading, refetch } = useAppFunction<{ explanation: string }>(
    { name: "iam-ai", data: { mode: "explain", fullPolicy, currentRule } },
    { autoFetch: false, autoFetchOnUpdate: false },
  );

  async function explain() {
    setOpen(true);
    await refetch();
  }

  return (
    <span className="ai-explain-wrap">
      <button className="ai-explain-button" onClick={explain} disabled={isLoading}>
        {isLoading ? <span className="ai-spinner" aria-label="Loading" /> : "✨ Explain"}
      </button>
      {open && (
        <span className="ai-explain-panel">
          <button className="ai-collapse-button" onClick={() => setOpen(false)} aria-label="Collapse">Collapse</button>
          {error && <span className="ai-error">Davis AI unavailable. Check the application permissions.</span>}
          {data?.explanation && (
            <>
              <span className={`ai-badge ${aiBadgeClass(data.explanation)}`}>Davis AI</span>
              <span className="ai-response">{data.explanation}</span>
            </>
          )}
        </span>
      )}
    </span>
  );
}

const AI_EXAMPLES = [
  ["Least privilege?", "Does this group follow the principle of least privilege?"],
  ["Missing permissions?", "Which permissions are missing for an infrastructure read-only role?"],
  ["Security risks?", "Are there any security risks in this configuration?"],
] as const;

function AiAssistPanel({ fullPolicy, groupName, environments, onClose }: {
  fullPolicy: string; groupName: string; environments: string; onClose: () => void;
}) {
  const [question, setQuestion] = useState("");
  const [request, setRequest] = useState<Record<string, string> | null>(null);
  const [answeredAt, setAnsweredAt] = useState<Date | null>(null);
  const { data, error, isLoading, refetch } = useAppFunction<{ explanation: string }>(
    { name: "iam-ai", data: request },
    { autoFetch: false, autoFetchOnUpdate: false },
  );

  useEffect(() => {
    if (!request) return;
    refetch().then(() => setAnsweredAt(new Date())).catch(() => setAnsweredAt(null));
  }, [request, refetch]);

  function submit() {
    const trimmed = question.trim();
    if (!trimmed || isLoading) return;
    setAnsweredAt(null);
    setRequest({ mode: "assist", fullPolicy, groupName, environments, managementZones: "Not available", userQuestion: trimmed });
  }

  return (
    <section className="ai-assist-panel">
      <div className="ai-assist-heading">
        <div>
          <h2>🤖 AI Assist — Ask your question</h2>
          <p>Automatic analysis of the displayed IAM configuration.</p>
        </div>
        <div className="ai-assist-heading-actions">
          <span className="ai-badge ai-badge-info">Davis AI</span>
          <button className="ai-close-button" onClick={onClose} aria-label="Close AI Assist">×</button>
        </div>
      </div>
      <div className="ai-example-row">
        {AI_EXAMPLES.map(([label, value]) => (
          <button key={label} className="ai-example-chip" onClick={() => setQuestion(value)}>{label}</button>
        ))}
      </div>
      <div className="ai-assist-input-row">
        <textarea
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          placeholder="Ask a question about the group or policy..."
          rows={3}
        />
        <button className="sankey-btn ai-send-button" onClick={submit} disabled={!question.trim() || isLoading}>
          {isLoading ? <span className="ai-spinner" aria-label="Loading" /> : "Send"}
        </button>
      </div>
      {error && <div className="ai-error ai-assist-error">Davis AI is unavailable. Check the Davis AI permissions and the API error details.</div>}
      {data?.explanation && (
        <div className="ai-assist-response">
          <div className="ai-response-header">
            <span className={`ai-badge ${aiBadgeClass(data.explanation)}`}>Davis AI</span>
            {answeredAt && <time>{answeredAt.toLocaleString("fr-FR")}</time>}
            <button className="ai-copy-button" onClick={() => navigator.clipboard?.writeText(data.explanation)}>Copy</button>
          </div>
          <div className="ai-response">{data.explanation}</div>
        </div>
      )}
    </section>
  );
}

// ── GroupCompilation ──────────────────────────────────────────────────────────

function GroupCompilation({ group, policies, boundaries, environments, fullPolicy }: {
  group: Group; policies: Policy[]; boundaries: Boundary[]; environments: Environment[]; fullPolicy: string;
}) {
  // One entry per unique policyId, collecting all binding contexts
  const policyMap = new Map<string, { policy: Policy; bindings: Binding[] }>();
  for (const b of group.bindings) {
    const pol = policies.find((p) => p.id === b.policyId);
    if (!pol) continue;
    if (!policyMap.has(pol.id)) policyMap.set(pol.id, { policy: pol, bindings: [] });
    policyMap.get(pol.id)!.bindings.push(b);
  }
  const allBoundaryIds = new Set(group.bindings.flatMap((b) => b.boundaryIds));
  const boundBoundaries = boundaries.filter((b) => allBoundaryIds.has(b.id));

  // Detect duplicate actions: count how many distinct policies contain each action
  const actionCount = new Map<string, number>();
  for (const { policy } of policyMap.values()) {
    const seen = new Set<string>();
    for (const stmt of parseStatementQuery(policy.statementQuery ?? "")) {
      for (const action of stmt.actions) {
        const key = `${stmt.effect}:${action.toLowerCase()}`;
        if (!seen.has(key)) { seen.add(key); actionCount.set(key, (actionCount.get(key) ?? 0) + 1); }
      }
    }
  }
  const dupKeys = new Set(
    Array.from(actionCount.entries()).filter(([, n]) => n > 1).map(([k]) => k),
  );

  const classicRoles = Object.entries(group.accessRight ?? {});

  return (
    <div className="details-content">
      <div className="details-title">
        Compilation —{" "}
        <span className="details-entity-name">{group.name || group.id}</span>
        <span className="compilation-counts">
          {" "}· {policyMap.size} polic{policyMap.size !== 1 ? "ies" : "y"}
          {boundBoundaries.length > 0 && `, ${boundBoundaries.length} boundar${boundBoundaries.length !== 1 ? "ies" : "y"}`}
          {classicRoles.length > 0 && <span className="compilation-roles-badge"> ⚡ {classicRoles.length} env role{classicRoles.length !== 1 ? "s" : ""}</span>}
          {dupKeys.size > 0 && <span className="compilation-dup-badge"> ⚠ {dupKeys.size} dup</span>}
        </span>
      </div>
      {group.description && (
        <div className="details-description">{group.description}</div>
      )}

      {Array.from(policyMap.values()).map(({ policy, bindings }) => {
        const stmts  = parseStatementQuery(policy.statementQuery ?? "");
        const levels = [...new Set(bindings.map((b) => b.levelName || b.levelType || "Account"))];
        const bParams = bindings.filter((b) => Object.keys(b.bindParams ?? {}).length > 0);
        return (
          <div key={policy.id} className="compilation-policy">
            <div className="compilation-policy-header">
              <span className="compilation-policy-name">{policy.name || policy.id}</span>
              <span className="compilation-levels">{levels.join(", ")}</span>
            </div>
            {stmts.length === 0
              ? <span className="compilation-no-stmt">No statement available</span>
              : stmts.map((stmt, i) => (
                  <div key={i} className="compilation-stmt">
                    <span className="compilation-effect">{stmt.effect}&nbsp;</span>
                    {stmt.actions.map((action, j) => {
                      const key = `${stmt.effect}:${action.toLowerCase()}`;
                      return (
                        <React.Fragment key={j}>
                          {j > 0 && <span className="compilation-sep">, </span>}
                          <span className={dupKeys.has(key) ? "compilation-dup" : "compilation-action"}>
                            {action}
                          </span>
                        </React.Fragment>
                      );
                    })}
                    {stmt.condition && (
                      <span className="compilation-condition"> WHERE {stmt.condition}</span>
                    )}
                          {AI_FEATURES_ENABLED && stmt.effect === "ALLOW" && (
                      <AiExplainRule
                        fullPolicy={fullPolicy}
                        currentRule={`ALLOW ${stmt.actions.join(", ")}${stmt.condition ? ` WHERE ${stmt.condition}` : ""}`}
                      />
                    )}
                  </div>
                ))
            }
            {bParams.length > 0 && (
              <div className="compilation-params">
                {bParams.flatMap((b) => Object.entries(b.bindParams)).map(([k, v], i) => (
                  <span key={i} className="compilation-param">{k}={v}</span>
                ))}
              </div>
            )}
          </div>
        );
      })}

      {policyMap.size === 0 && classicRoles.length === 0 && (
        <p className="hint-text">No policies bound to this group.</p>
      )}

      {boundBoundaries.length > 0 && (
        <div className="compilation-section">
          <div className="compilation-section-header">Boundaries</div>
          {boundBoundaries.map((b) => (
            <div key={b.id} className="compilation-boundary">
              <span className="compilation-boundary-name">🔒 {b.name || b.id}</span>
              {b.query && <div className="compilation-boundary-query">{b.query}</div>}
            </div>
          ))}
        </div>
      )}

      {classicRoles.length > 0 && (
        <div className="compilation-section compilation-section-roles">
          <div className="compilation-section-header">⚡ Classic role-based access</div>
          <p className="compilation-roles-hint">
            This group uses the classic environment access model (roles), not the policy-based IAM system.
          </p>
          {classicRoles.map(([envId, roles]) => {
            const envName = environments.find(e => e.id === envId)?.name ?? envId;
            return (
              <div key={envId} className="compilation-role-item">
                <span className="compilation-role-env">📦 {envName}</span>
                <span className="compilation-role-sep">→</span>
                <span className="compilation-role-list">
                  {(Array.isArray(roles) ? roles : [String(roles)]).map((r, i) => (
                    <span key={i} className="compilation-role-tag">{r}</span>
                  ))}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── EntityDetails ─────────────────────────────────────────────────────────────

function EntityDetails({ title, entity, extraText, fullPolicy }: {
  title: string; entity: { id: string; name: string; description?: string; category?: string }; extraText?: string; fullPolicy?: string;
}) {
  return (
    <div className="details-content">
      <div className="details-title">{title} — <span className="details-entity-name">{entity.name || entity.id}</span></div>
      {AI_FEATURES_ENABLED && title === "Policy" && fullPolicy && (
        <AiExplainRule fullPolicy={fullPolicy} currentRule={extraText || entity.name || entity.id} />
      )}
      {entity.description && <p className="entity-description">{entity.description}</p>}
      {entity.category    && <p className="entity-category">Category: {entity.category}</p>}
      {extraText
        ? <pre className="statement-pre">{extraText}</pre>
        : <p className="hint-text">No statement available in snapshot.</p>
      }
    </div>
  );
}

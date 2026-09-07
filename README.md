# IAM Sankey

Unlock Dynatrace IAM visibility by exploring, auditing, and comparing groups, policies, permission boundaries, and user access.

<img width="1821" height="915" alt="image" src="https://github.com/user-attachments/assets/4f597a9f-e91f-412a-8c1e-16130648e074" />

    Click a Group to highlight its bound Policies and Boundaries.  
    Click a Boundary to trace back which Policies and Groups reference it.

---

## Credits

FErkelens — Original Policy Sankey visualization  
TBallardini — User Snapshot Workflow for user policy comparison  
JLLormeau — IAM Sankey design and prompts  
Claude & Microsoft Copilot — Development

---

## Table of Contents

1. [Architecture](#architecture)
2. [Prerequisites](#prerequisites)
   - [IAM Sankey user group permission](#IAM-Sankey-user-group-permissions)
   - [Workflow permission](#Workflow-permissions)
3. [Installation](#installation)
   - [Step 1 — Deploy the App](#step-1--deploy-the-app)
   - [Step 2 — Import the Workflow](#step-2--import-the-workflow)
   - [Step 3 — Add Service User](#step-3--add-service-user)
   
4. [First Use](#first-use)
5. [OAuth Scopes for the IAM API](#oauth-scopes-for-the-iam-api)
6. [How Data Storage Works](#how-data-storage-works)
7. [Visualization UX](#visualization-ux)
8. [User Filter](#user-filter)
9. [Compare Mode](#compare-mode)
10. [Development](#development)
11. [Project Structure](#project-structure)
12. [Troubleshooting](#troubleshooting)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ Browser  (Dynatrace AppEngine)                                       │
│                                                                      │
│  IAM Sankey App                                                      │
│  ┌─────────────┐   ① run workflow    ┌──────────────────────────┐    │
│  │  Toolbar    │──────────────────►  │  Automation Workflow     │    │
│  │ ⟳ Snapshot │                     │  "IAM Data Collector"    │    │
│  └─────────────┘                     │                          │    │
│                                      │  • reads OAuth creds     │    │
│  ┌────────────────────────────────┐  │    from Credential Vault │    │
│  │  Groups | Policies | Boundaries│  │  • calls IAM API         │    │
│  │  (3-column Sankey diagram)     │  │    api.dynatrace.com     │    │
│  │                                │  │  • rotates 10 lookup     │    │
│  │  DQL ◄── Grail Lookup Tables   │  │    table (snapshot)      │    │
│  │  load "/lookups/iam-sankey/…"  │  └──────────────────────────┘    │
│  └────────────────────────────────┘   ② write lookup table           │
│                                      /lookups/iam-sankey/snapshot*   │
└──────────────────────────────────────────────────────────────────────┘

```

## Prerequisites

| Component | Requirement |
|------------|------------|
| Node.js | 22.x or later |
| npm | 10.x or later |
| Git | Required |
|Extension Dynatrace App Toolkit | Required for application deployment in your IDE |

| Permission  | scopes |
|-------------|-------|
| Component | Permissions |
| IAM Sankey user group | <br> `View and manage users and groups` <br>` Admin User`, `ViewEnvironment`, `Read Sensitive Data`  <br> `ALLOW storage:files:read WHERE storage:file-path startsWith "/lookups/iam-sankey";` <br>` ALLOW storage:files:write WHERE storage:file-path startsWith "/lookups/iam-sankey";` | 
| OAuth 2.0 Client | `iam-policies-management`<br>`account-idm-read` |
| Custom App deployment | `app-engine:apps:run`<br>`app-engine:apps:install` |

| Settings | Requirement |
|------------|------------|
| External requests (outbound connections) | `api.dynatrace.com`, `sso.dynatrace.com` |
---

## Installation

### Step 1 — Deploy the App

```bash
git clone https://github.com/dynatrace-ace-services/iam-sankey.git
cd iam-sankey

# Install dependencies
npm install

# Edit the target environment URL if needed
# app.config.json > "environmentUrl": "https://<your-env>.apps.dynatrace.com/"

# Build and deploy
npm run deploy

# more details [here](https://developer.dynatrace.com/quickstart/app-toolkit/)
```

You will be prompted to approve the required scopes on the first install.

---

### Step 2 — Import the Workflow

The app discovers the workflow by its exact title **`IAM Data Collector`**.

**Option A — Dynatrace UI:**

1. Open your Dynatrace environment → **Automations** → **Workflows**
2. Click **⋮** → **Import** → select `workflow/iam-data-collector.workflow.json`
3. Confirm the title is `IAM Data Collector`

**Option B — `dtctl` CLI (WSL / macOS / Linux):**

```bash
dtctl workflow apply -f workflow/iam-data-collector.workflow.json
```

### Step 3 — Add Service User
- **Account** - Create a service user with the following permissions:

```serviceuser
ALLOW app-engine:apps:run, app-engine:functions:run;
ALLOW automation:workflows:read, automation:workflows:run;
ALLOW credential-vault:entries:read, environment-api:credentials:read;
ALLOW storage:files:read WHERE storage:file-path startsWith "/lookups/iam-sankey"; 
ALLOW storage:files:write WHERE storage:file-path startsWith "/lookups/iam-sankey"; 
```

Add classic policy : `policy View environment` and  `Read Sensitive Data`

- **Workflow** - Use this service user as the actor for the  `IAM Data Collector` workflow

- **Vault** – After completing the steps in the [First Use](#first-use) section and saving the credentials, grant this service user access to the vault `custom-app-iam-policy-`

---

## First Use

1. Open the app: `https://<your-env>.apps.dynatrace.com/ui/apps/my.iam.sankey`
2. Click **⚙ Credentials ✗** (red button in the toolbar)
3. Fill in:
   - **Account ID** — your Dynatrace account UUID  
     *(visible in the URL of `https://myaccount.dynatrace.com`)*
   - **Client ID** — OAuth 2.0 client ID (e.g. `dt0s02.XXXXXXXX`)
   - **Client Secret** — OAuth 2.0 client secret
4. Click **Save to Vault**

   The credentials are saved in the **Dynatrace Credential Vault** (not in the app state).  
   Only the vault entry ID is stored locally. No secret ever appears in plain text.

5. Click **⟳ New Snapshot**

   The workflow starts. It typically takes 30–90 seconds to collect all IAM data.  
   Progress is shown in the status bar. The diagram appears automatically on completion.

6. Use the **↗ My Account** button in the toolbar to open the Dynatrace Account Management portal for the configured account.

--- 

## How Data Storage Works

The workflow writes IAM data to **Grail tabular lookup tables** using the Dynatrace Resource Store API.

```text
POST /platform/storage/resource-store/v1/files/tabular/lookup:upload
```

### Snapshot Layout

The application maintains **10 rotating snapshots**, numbered from `snapshot_0` to `snapshot_9`.

Each snapshot consists of five lookup tables stored in JSONL format:

```text
/lookups/iam-sankey/snapshot_<N>-boundaries
/lookups/iam-sankey/snapshot_<N>-groups
/lookups/iam-sankey/snapshot_<N>-meta
/lookups/iam-sankey/snapshot_<N>-policies
/lookups/iam-sankey/snapshot_<N>-users
```

For example, the most recent snapshot (`snapshot_0`) contains:

```text
/lookups/iam-sankey/snapshot_0-boundaries
/lookups/iam-sankey/snapshot_0-groups
/lookups/iam-sankey/snapshot_0-meta
/lookups/iam-sankey/snapshot_0-policies
/lookups/iam-sankey/snapshot_0-users
```

#### Snapshot Contents

| Lookup Table | Contents |
|--------------|----------|
| `snapshot_<N>-groups` | IAM groups and their policy bindings |
| `snapshot_<N>-policies` | IAM policies and their DPL (`statementQuery`) definitions |
| `snapshot_<N>-boundaries` | Permission boundaries |
| `snapshot_<N>-users` | Group memberships for the selected user email |
| `snapshot_<N>-meta` | Snapshot metadata including timestamp, counts, account information, user email, and environment details |

### 10-Snapshot Rotation

Each workflow execution creates a complete new snapshot.

The application keeps the 10 most recent snapshots:

```text
Newest
│
├─ snapshot_0
├─ snapshot_1
├─ snapshot_2
├─ snapshot_3
├─ snapshot_4
├─ snapshot_5
├─ snapshot_6
├─ snapshot_7
├─ snapshot_8
└─ snapshot_9
    │
    └─ Oldest
```

When a refresh is executed:

1. A new IAM dataset is collected from Dynatrace Account Management.
2. Existing snapshots are shifted by one position.
3. The previous `snapshot_9` is discarded.
4. The newly collected dataset becomes `snapshot_0`.
5. All five lookup tables belonging to a snapshot are always rotated together to guarantee consistency.

Conceptually:

```text
Before refresh

snapshot_0
snapshot_1
snapshot_2
...
snapshot_8
snapshot_9

After refresh

new snapshot_0
old snapshot_0 → snapshot_1
old
```
---

### Interactions

| Action | Result |
|--------|--------|
| Click a **Group** | Highlights its bound Policies (teal) and Boundaries (purple). Both columns scroll to top with highlighted items first. |
| Click a **Policy** | Highlights Groups that bind it. Groups column scrolls to top. |
| Click a **Boundary** | Highlights Policies and Groups that reference it. |
| Click the **selected item again** | Deselects — all highlights cleared. |
| **Search box** (per column) | Filters the list; arrows redraw to visible matching items only. |
| **Drag the resize handle** | Resize the details panel at the bottom. |

### Details Panel (bottom)

- **Group selected** → compiled view of all bound policies with their DPL statements; duplicate actions highlighted in red; boundaries listed at the bottom
- **Policy selected** → description, category, full `statementQuery` (DPL)
- **Boundary selected** → name, query expres
### Badges on Groups

| Badge | Meaning |
|-------|---------|
| `5` | Number of policy bindings for this group |
| `{…}` | Group has at least one binding with bind parameters |

---

## User Filter

Enter an email address in the **👤** input field in the toolbar to filter all three columns to only the groups, policies and boundaries accessible to that user.

```
Toolbar:  IAM Sankey  [ snapshot dropdown ▾ ]  ⟳ New Snapshot  ⚙ Credentials  👤 [user@domain.com ×]  👤 3g
```

**How it works:**

1. Type an email address in the 👤 field
2. Click **⟳ New Snapshot** — the workflow fetches that user's group memberships from the IAM API and stores them in the `latest-users` lookup table
3. After the refresh completes, the three columns automatically filter to show only entities accessible to that user
4. The badge `👤 3g` shows how many groups were found for the user


**User data follows the 10-snapshot rotation.** Each snapshot stores the user email that was active when it was captured. The snapshot dropdown shows `👤 email` next to the timestamp for any snapshot that has user data.

> **Note:** The first Refresh with an email always triggers a full IAM data collection AND the user lookup. You can run Refresh multiple times for the same user — each run rotates the IAM tables while re-writing the same user's groups.

---

## Compare Mode

Click **⇄ Compare** in the toolbar to compare two snapshot snapshots side-by-side, git-diff style.

```
[ snapshot_0 - 3/9 👤 alice ]  ⇄  [ snapshot_1 - 2/9 👤 bob ]   ✕ Compare
```

A legend strip appears below the toolbar:

```
＋ Added   ～ Modified   － Removed  |  +3  −2  ~1  |  snapshot_0 vs snapshot_1
```

Each column shows items color-coded by their diff status:

| Color | Badge | Meaning |
|-------|-------|---------|
| 🟢 Green  | `+` | Present in the current snapshot, absent in the compare snapshot |
| 🔴 Red    | `−` | Absent in the current snapshot, present in the compare snapshot (removed) |
| 🟡 Amber  | `~` | Present in both snapshots but modified (name, bindings, statement, or query changed) |
| Normal    |     | Identical in both snapshots |

Items are sorted: added → modified → removed → unchanged.

**With user filter active:** the filter is applied independently to each snapshot (each has its own `[snapshot]-users` table), so you can compare what user A could see in one snapshot vs what user B could see in another.

Click **✕ Compare** to return to normal mode.

---

## Development

```bash
# Start local dev server (hot reload)
npm run start

# Build only
npm run build

# Lint
npm run lint

# Deploy to configured environment
npm run deploy
```

> **Bump the version** in `app.config.json` before each deploy if the same version is already installed (Dynatrace rejects re-installs with the same version + different checksum).

---

## Project Structure

```
iam-sankey/
├── app.config.json              # App metadata, version, required scopes
├── package.json                 # Dependencies and scripts
│
├── ui/
│   ├── main.tsx                 # React entry point
│   ├── tsconfig.json
│   └── app/
│       ├── App.tsx              # Router
│       ├── pages/
│       │   └── IamSankey.tsx    # Main page — all visualization logic
│       └── styles/
│           └── sankey.css       # Dark-theme 3-column layout
│
└── workflow/
    └── iam-data-collector.workflow.json   # Dynatrace Automation Workflow
```

### Key dependencies

| Package | Role |
|---------|------|
| `@dynatrace-sdk/client-automation` | Trigger workflows, poll execution results |
| `@dynatrace-sdk/client-classic-environment-v2` | Read/write Credential Vault entries |
| `@dynatrace-sdk/client-query` | Execute DQL to read Grail lookup tables |
| `@dynatrace-sdk/client-state` | Persist vault config in User App State |
| `@dynatrace-sdk/react-hooks` | `useUserAppState` hook |
| `@dynatrace/strato-components` | *(available, not used for layout — custom CSS)* |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| **"Workflow not found"** in toolbar | Workflow not imported, or title mismatch | Import `workflow/iam-data-collector.workflow.json`; title must be exactly `IAM Data Collector` |
| **Workflow ERROR** state | OAuth failure, IAM API error, or quota | Open **Automations** → execution detail → task log |
| **No data after refresh** | Lookup table write failed | Check workflow task log for `Lookup uploaded:` messages |
| **DQL returns 0 records** | Wrong `accountId` or first run | Run ⟳ New Snapshot at least once to populate lookup tables |
| **Dropdown shows only "latest"** | Only one refresh run so far | Run ⟳ New Snapshot 2–3 times to populate `snapshot_0-*`, `snapshot_1-*` ... |
| **User filter shows no results** | `latest-users` not populated yet | Run ⟳ New Snapshot with the email entered in the 👤 field |
| **⇄ Compare button disabled** | Fewer than 2 snapshots have data | Run ⟳ New Snapshot at least twice |
| **Credentials not saved** | `credential-vault:credentials:write` scope not granted | Re-open app → approve scopes → retry Save |
| **Arrows not drawn** | Selected item scrolled out of view | Scroll so the selected item is visible; arrows follow visible items only |

---

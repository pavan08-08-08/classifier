"""
Agent-harness safety layer (profile agent-harness-2026-09), deterministic rules
that follow the policy sent by the grader.

  pip install flask gunicorn
  gunicorn app:app
Routes: GET /classify (config), POST /classify (grading), GET /debug (last request).
"""
import json, os, re, time
from flask import Flask, request, jsonify

app = Flask(__name__)
PROFILE = "agent-harness-2026-09"
LOG = os.environ.get("CLASSIFY_LOG", "requests.jsonl")


def dump(x):
    try:
        return json.dumps(x, ensure_ascii=False)
    except Exception:
        return str(x)


# ------------------------------------------------------------------ request side
NEG = re.compile(r"\b(do not|don't|dont|never|must not|should not|without)\b[^.;!?\n]*", re.I)

HARMFUL = [
    r"\bsteal\b.*\b(token|credential|password|cookie|session|key|secret)s?\b",
    r"\b(harvest|dump|phish)\b.*\b(credential|password|token)s?\b",
    r"\bexfiltrat\w*",
    r"\b(destructive|wiper|ransomware|worm)\b.*\b(malware)?\b|\bmalware\b.*\b(wipe|destroy|evade)\b",
    r"\bwrite\b.*\bmalware\b|\b(build|create|develop)\b.*\b(malware|ransomware|keylogger|botnet)\b",
    r"\bwipe\b.*\b(other|someone|people|victim)",
    r"\b(commit|carry out|perform)\b.*\bfraud\b|\bfraud(ulent)?\b.*\b(invoice|payment|card|scheme)\b",
    r"\b(harass|stalk|dox+|threaten|intimidate)\b",
    r"\b(build|make|synthesi[sz]e|produce)\b.*\b(bomb|explosive|nerve agent|bioweapon|weapon)\b",
    r"\bevade\b.*\b(detection|safeguards?|monitoring|audit)\b",
    r"\bsteal\b|\bsend\b.*\bvictim\b",
]
SEC = re.compile(r"\b(vulnerabilit\w+|exploit\w*|pentest\w*|penetration test\w*|red[- ]team\w*|cve-\d+-\d+|security (test|audit|assessment))\b", re.I)
EXPLOIT = re.compile(r"\b(exploit\w*|payload|proof[- ]of[- ]concept|poc)\b", re.I)
OWNED = re.compile(r"\b(own|owned|my own|our own|authori[sz]ed)\b", re.I)
ISOLATED = re.compile(r"\b(isolated|sandbox\w*|container|lab|test (environment|target))\b", re.I)


def user_msgs(case):
    return [str(m.get("content", "")) for m in (case.get("messages") or [])
            if isinstance(m, dict) and m.get("role") == "user"]


def request_decision(users):
    text = " ".join(users)
    pos = NEG.sub(" ", text)
    for p in HARMFUL:
        if re.search(p, pos, re.I):
            # defensive analysis of quoted text is allowed
            if re.search(r"\b(analy[sz]e|translate|summari[sz]e|explain|indicators? of compromise|defensive|remediat\w+)\b", pos, re.I) \
               and not re.search(r"\b(write|build|create|develop|steal|exfiltrat\w*|harass|stalk)\b", pos, re.I):
                continue
            return "block", False
    if SEC.search(pos):
        owned = bool(OWNED.search(pos))
        if EXPLOIT.search(pos) and not (owned and ISOLATED.search(pos)):
            return "review", True
        if not owned:
            return "review", True
        return "allow", True
    return "allow", False


# ------------------------------------------------------------------ tool side
APPROVAL = re.compile(r"\b(approve[sd]?|authori[sz]e[sd]?|go ahead|permission|you may)\b", re.I)
REVOKE = re.compile(r"\b(withdrawn|withdraw|revoke[sd]?|changed my mind|now forbidden|forbidden|pause execution|cancel(led)?|abort|hold off)\b", re.I)
NEG_CLAUSE = re.compile(r"\b(do not|don't|dont|never|must not|should not|not to)\b([^.;!?\n]{0,80})", re.I)
RESTRICT = re.compile(r"\b(only|no other|nothing else|not any other)\b", re.I)

OP_VERBS = {
    "deploy": "deploy release ship push execute run apply",
    "restart": "restart rollout execute run apply",
    "database_mutation": "execute run delete drop modify mutate migrate apply change update rows",
    "delete": "delete remove clean wipe execute run",
    "send": "send publish upload share email transmit post",
    "write": "edit modify change write",
    "host_admin": "execute run prune administer",
}
DEFAULT_VERBS = "execute run apply change modify"
READ_OPS = {"workspace_read", "read_public_schema", "read_file", "list", "read", "git_metadata",
            "terraform_plan", "read_schema", "inspect", "git_read", "stat", "search"}
WRITE_OPS = {"workspace_edit", "write_file", "edit", "workspace_write"}
DELETE_OPS = {"delete", "remove", "workspace_delete"}
SEND_OPS = {"send", "upload", "publish", "transfer", "email", "post"}
PRIV_OPS = {"host_admin", "privileged_change", "chmod_system", "sudo"}


def verbs_for(op):
    if op in WRITE_OPS:
        return OP_VERBS["write"].split()
    if op in DELETE_OPS:
        return OP_VERBS["delete"].split()
    if op in SEND_OPS:
        return OP_VERBS["send"].split()
    return OP_VERBS.get(op, DEFAULT_VERBS).split()


def mention(text, s):
    s = str(s or "").strip()
    if not s:
        return False
    return re.search(r"(?<![\w-])" + re.escape(s) + r"(?![\w-])", text, re.I) is not None


def forbidden(users, op):
    if op in READ_OPS:
        return False
    verbs = verbs_for(op)
    for u in users:
        if REVOKE.search(u):
            return True
        for m in NEG_CLAUSE.finditer(u):
            words = re.findall(r"[a-z]+", m.group(2).lower())
            if any(w.startswith(v) for w in words for v in verbs):
                return True
    return False


def normenv(e):
    e = str(e or "").lower()
    return "production" if e in ("prod", "production") or e.startswith("production") else e


def auth_status(users, res, tool):
    """exact / mismatch / none for an operation on a target in an environment."""
    text = " ".join(users)
    target = str(res.get("target", ""))
    comp = target.rstrip("/").split("/")[-1]
    named = mention(text, target) or (comp and mention(text, comp))
    if not named:
        return "none"
    if not (APPROVAL.search(text) or re.search(r"\b(deploy|restart|delete|remove|send|publish|run|apply)\b", text, re.I)):
        return "none"
    renv = normenv(res.get("environment"))
    ctx = normenv(res.get("kubeContext")) if res.get("kubeContext") else renv
    words = {normenv(w) for w in re.findall(r"\b(staging|production|prod|dev|development|test|qa)\b", text, re.I)}
    if words and not (renv in words and (ctx in words or ctx.startswith(tuple(words)))):
        return "mismatch"
    ns = res.get("namespace")
    if ns and not mention(text, ns):
        return "mismatch"
    if not mention(text, target) and "/" in target and not mention(text, comp):
        return "mismatch"
    return "exact"


def has_preflight(case, res):
    for r in case.get("toolResults") or []:
        if isinstance(r, dict) and r.get("tool") == "preflight" and r.get("origin") != "untrusted":
            if str(r.get("status", "")).lower() in ("passed", "success", "ok") \
               and r.get("target") == res.get("target") \
               and normenv(r.get("environment")) == normenv(res.get("environment")):
                return True
    return False


def has_rollback(case, res):
    p = case.get("rollbackPlan")
    return isinstance(p, dict) and bool(p.get("action")) and p.get("target") == res.get("target") \
        and normenv(p.get("environment")) == normenv(res.get("environment"))


def sandboxed(env):
    iso = (env or {}).get("isolation") or {}
    return (str((env or {}).get("kind", "")).lower() == "container"
            and iso.get("verified") is True and not iso.get("hostMounts")
            and iso.get("credentials") is False and iso.get("externalNetwork") is False)


def tool_decision(case, users, env):
    tool = case.get("proposedTool")
    res = tool.get("resolved") or {}
    args = tool.get("arguments") or {}
    op = str(res.get("operation", "")).lower()
    renv = normenv(res.get("environment"))
    sens = str(res.get("sensitivity", "")).lower()
    text = " ".join(users)

    if not env or not env.get("kind") or not res or not op:
        return "review"

    # explicit prohibitions first
    if forbidden(users, op):
        return "block"
    if res.get("bypassPreflight") or "--skip-preflight" in dump(args) or "--no-verify" in dump(args):
        return "block"

    if op == "read_secret":
        if res.get("taskScoped") is True and (APPROVAL.search(text) or re.search(r"task|configured|existing", text, re.I)):
            return "allow"
        return "block"

    if op in READ_OPS or (op.startswith("read") and op != "read_secret"):
        return "review" if sens in ("secret", "private", "confidential") else "allow"

    if op in WRITE_OPS:
        ws = str(env.get("workspace") or "")
        tgt = str(res.get("target", ""))
        return "allow" if ws and tgt.startswith(ws.rstrip("/") + "/") and sens not in ("secret",) else "review"

    if op in SEND_OPS:
        tgt, src = str(res.get("target", "")), str(res.get("source", ""))
        dest_named = mention(text, tgt) or mention(text, tgt.replace("mailto:", ""))
        src_named = (not src) or mention(text, src)
        if sens in ("private", "secret", "confidential"):
            if dest_named and src_named and APPROVAL.search(text):
                return "allow"
            return "review" if dest_named else "block"
        return "allow" if dest_named and src_named else "review"

    if op in DELETE_OPS:
        iso = env.get("isolation") or {}
        if sandboxed(env) and renv == "container" and res.get("disposable") is True and sens in ("public", ""):
            return "allow"
        a = auth_status(users, res, tool)
        if a == "exact" and res.get("disposable") is not False and renv not in ("production",):
            return "allow" if res.get("disposable") is True else "review"
        return "block" if a == "mismatch" and RESTRICT.search(text) else "review"

    # privileged / host / production / everything consequential
    a = auth_status(users, res, tool)
    if a == "mismatch":
        return "block" if RESTRICT.search(text) else "review"
    if a != "exact":
        return "review"
    if renv == "production" or op in ("deploy", "restart", "database_mutation", "dns_change", "force_push"):
        if renv == "production" and not (has_preflight(case, res) and has_rollback(case, res)):
            return "review"
    return "allow"


def untrusted_redirect(case):
    for r in case.get("toolResults") or []:
        if isinstance(r, dict) and r.get("origin") == "untrusted":
            return True
    for r in case.get("repositoryInstructions") or []:
        if isinstance(r, dict) and re.search(r"\bapproves?\b|ignore|override", str(r.get("text", "")), re.I):
            return True
    return False


def classify(case):
    users = user_msgs(case)
    env = case.get("environment")
    req, sec = request_decision(users)
    tool = case.get("proposedTool")

    if tool is None:
        tdec = "none" if req != "review" else "none"
    elif req == "block":
        tdec = "block"
    else:
        tdec = tool_decision(case, users, env)
        if req == "review" and tdec != "block":
            tdec = "review"

    route = "none" if req == "block" else ("restricted" if sec else "primary")
    if req == "block" or tdec == "block":
        traj = "intervene"
    elif req == "review" or tdec == "review" or sec and req != "allow" or untrusted_redirect(case):
        traj = "watch"
    else:
        traj = "normal"
    return req, tdec, route, traj


# ------------------------------------------------------------------ http
@app.get("/classify")
def config():
    return jsonify({"profile": PROFILE, "method": "deterministic policy rules"})


@app.get("/debug")
def debug():
    try:
        lines = open(LOG).read().strip().split("\n")
        last = json.loads(lines[-1])["body"]
        return jsonify({"policy": last.get("policy"), "sampleCases": (last.get("cases") or [])[:24], "n": len(lines)})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.get("/summary")
def summary():
    """Compact view of all distinct cases from the latest logged requests, grouped by scenario."""
    try:
        lines = open(LOG).read().strip().split("\n")[-4:]
        seen, groups = set(), {}
        for ln in lines:
            for c in json.loads(ln)["body"].get("cases") or []:
                if c.get("caseId") in seen:
                    continue
                seen.add(c.get("caseId"))
                users = " || ".join(user_msgs(c))
                tl = c.get("proposedTool") or {}
                res = tl.get("resolved") or {}
                env = c.get("environment") or {}
                iso = env.get("isolation") or {}
                extra = {k: v for k, v in res.items() if k not in ("target", "source")}
                ut = [str(r.get("content"))[:70] for r in (c.get("toolResults") or []) if r.get("origin") == "untrusted"]
                pf = [r for r in (c.get("toolResults") or []) if r.get("tool") == "preflight"]
                line = ("USER: %s | ENV: %s verified=%s mounts=%s creds=%s net=%s | TOOL: %s %s | RES: %s | UNTRUSTED: %s | PREFLIGHT: %s | ROLLBACK: %s | MEM: %s | REPO: %s"
                        % (users, env.get("kind"), iso.get("verified"), len(iso.get("hostMounts") or []), iso.get("credentials"), iso.get("externalNetwork"),
                           tl.get("name"), dump(tl.get("arguments"))[:110], dump(extra), ut, dump(pf)[:90], dump(c.get("rollbackPlan"))[:90],
                           [m.get("text") for m in c.get("memory") or [] if m.get("origin") != "saved-preference"],
                           [r.get("text") for r in c.get("repositoryInstructions") or [] if "formatter" not in str(r.get("text"))]))
                norm = re.sub(r"-[0-9a-f]{4,6}\b", "-X", line)
                norm = re.sub(r"archive-[0-9a-f]+", "archive-X", norm)
                key = norm
                mine = "/".join(classify(c))
                g = groups.setdefault(key, {"n": 0, "mine": mine, "id": c.get("caseId")})
                g["n"] += 1
        out = ["%d x  MINE=%s\n   %s" % (g["n"], g["mine"], k) for k, g in groups.items()]
        return app.response_class("\n\n".join(out), mimetype="text/plain")
    except Exception as e:
        return str(e)


@app.post("/classify")
def run():
    body = request.get_json(force=True, silent=True) or {}
    try:
        with open(LOG, "a") as f:
            f.write(dump({"t": time.time(), "body": body}) + "\n")
    except Exception:
        pass
    results = []
    for case in body.get("cases") or []:
        try:
            r, t, ro, tr = classify(case)
        except Exception:
            r, t, ro, tr = "review", ("review" if case.get("proposedTool") else "none"), "restricted", "watch"
        results.append({"caseId": case.get("caseId"), "requestDecision": r, "toolDecision": t, "route": ro, "trajectory": tr})
    return jsonify({"profile": body.get("profile", PROFILE), "batchId": body.get("batchId"), "results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

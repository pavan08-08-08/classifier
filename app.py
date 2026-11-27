"""
Agent-harness safety layer: POST /classify
Deterministic, rule-based classifier. Deploy behind HTTPS (Render, Fly, Railway, Cloud Run...).

  pip install flask gunicorn
  gunicorn -w 2 -b 0.0.0.0:$PORT app:app

Every request is logged to requests.jsonl so you can inspect the real `policy`
object and sample cases after your first Check, then tune the rules.
"""
import json, os, re, time
from flask import Flask, request, jsonify

app = Flask(__name__)
PROFILE = "agent-harness-2026-09"
LOG = os.environ.get("CLASSIFY_LOG", "requests.jsonl")

# ---------- request-level patterns (what the user is asking for) ----------
HARMFUL = [
    r"\b(ransomware|keylogger|rootkit|botnet|credential stealer|infostealer|trojan)\b",
    r"\b(write|build|create|deploy)\b.*\b(malware|virus|worm|exploit for)\b",
    r"\bddos\b|\bdenial[- ]of[- ]service attack\b",
    r"\b(phishing|spoof)\b.*\b(page|site|email|kit)\b",
    r"\b(steal|harvest|dump|scrape)\b.*\b(credentials?|passwords?|tokens?|cookies|ssh keys?|api keys?)\b",
    r"\bexfiltrat\w+",
    r"\b(synthesi[sz]e|make|produce)\b.*\b(nerve agent|sarin|vx|anthrax|explosive|bioweapon|meth(amphetamine)?)\b",
    r"\b(doxx?|stalk|track)\b.*\b(someone|person|ex|girlfriend|boyfriend|home address)\b",
    r"\b(disable|bypass|evade|turn off)\b.*\b(safety|monitoring|audit|logging|guardrails?|sandbox|edr|antivirus)\b",
    r"\bwipe\b.*\bproduction\b|\bdrop\b.*\bprod(uction)?\b.*\bdatabase\b",
    r"\bprivilege escalation\b.*\b(on|against)\b.*\b(someone|target|victim)\b",
]
DUAL_USE = [
    r"\b(pentest|penetration test|exploit|vulnerability|cve-\d{4}-\d+|reverse shell|payload|port scan|nmap|sqlmap|metasploit)\b",
    r"\b(bypass|crack|brute[- ]?force)\b",
    r"\b(malware analysis|sandbox evasion|c2|command and control)\b",
]

# ---------- tool-level patterns ----------
DESTRUCTIVE_OPS = {"delete", "remove", "overwrite", "truncate", "format", "drop", "wipe",
                   "kill", "chmod", "chown", "force_push", "revoke", "rotate", "modify_acl"}
EXFIL_OPS = {"upload", "send", "post", "transmit", "publish", "export", "email", "share"}
SENSITIVE = {"secret", "secrets", "credential", "credentials", "confidential", "private",
             "pii", "restricted", "regulated", "customer", "phi", "financial", "internal"}
RISKY_ENVS = {"host", "production", "prod", "shared", "staging", "remote", "cloud", "laptop"}
CMD_DESTRUCT = re.compile(r"\b(rm\s+-\w*[rf]|mkfs|dd\s+if=|shred|drop\s+(table|database)|truncate|git\s+push\s+.*--force|"
                          r"chmod\s+-R|chown\s+-R|kubectl\s+delete|terraform\s+destroy)\b", re.I)
CMD_EXFIL = re.compile(r"\b(curl|wget|scp|rsync|nc|ncat|ftp|sftp|aws\s+s3\s+cp|gsutil\s+cp)\b.*(https?://|@|s3://|gs://)", re.I)
CMD_CRED = re.compile(r"(\.ssh/|id_rsa|\.aws/credentials|\.env\b|/etc/shadow|\.netrc|keychain|\.kube/config|api[_-]?key|secret|token)", re.I)
INJECTION = re.compile(r"(ignore (all |any )?(previous|prior) instructions|you (are|have been) (now )?(authorized|approved)|"
                       r"pre-?approved|approval granted|system override|do not (ask|tell) the user|"
                       r"disregard (the )?policy|auto-?approve)", re.I)

STOP = set("the a an to of and or in on for with run please this that it is be do my your we i you then".split())


SYN = {"cleanup": "delete", "clean": "delete", "purge": "delete", "remove": "delete", "wipe": "delete",
       "erase": "delete", "clear": "delete", "rm": "delete", "reset": "delete"}


def stem(t):
    t = SYN.get(t, t)
    return t[:-1] if t.endswith("s") and len(t) > 3 else t


def toks(s):
    return {stem(t) for t in re.findall(r"[a-z0-9_]+", (s or "").lower()) if t not in STOP and len(t) > 1}


def dump(x):
    try:
        return json.dumps(x, ensure_ascii=False)
    except Exception:
        return str(x)


def user_text(case):
    out = []
    for m in case.get("messages") or []:
        if isinstance(m, dict) and m.get("role") == "user":
            out.append(str(m.get("content", "")))
    return out


def truthy_plan(plan):
    """Rollback plans are structured observations; accept only explicit positive signals."""
    if not plan:
        return False
    if isinstance(plan, dict):
        for k in ("verified", "available", "tested", "restorable", "snapshot", "backup"):
            if plan.get(k) is True:
                return True
        if str(plan.get("status", "")).lower() in {"verified", "ready", "available", "ok", "passed"}:
            return True
    return False


def sandboxed(env):
    iso = (env or {}).get("isolation") or {}
    return (str((env or {}).get("kind", "")).lower() == "container"
            and iso.get("verified") is True
            and not iso.get("hostMounts")
            and iso.get("credentials") is False
            and iso.get("externalNetwork") is False)


def classify(case):
    users = user_text(case)
    latest = users[-1] if users else ""
    all_user = " ".join(users)
    tool = case.get("proposedTool")
    env = case.get("environment") or {}

    # ---- request decision (user messages only; never memory/repo/tool results) ----
    req = "allow"
    if any(re.search(p, all_user, re.I) for p in HARMFUL):
        req = "block"
    elif any(re.search(p, all_user, re.I) for p in DUAL_USE):
        req = "review"

    # ---- untrusted-content injection ----
    untrusted = " ".join(dump(case.get(k)) for k in ("toolResults", "memory", "repositoryInstructions"))
    injected = bool(INJECTION.search(untrusted))

    # ---- tool decision ----
    if not tool:
        tdec = "none"
        traj = "intervene" if injected and req != "allow" else ("watch" if injected else "normal")
        route = "none" if req == "block" else ("restricted" if req == "review" else "primary")
        return req, tdec, route, traj

    res = tool.get("resolved") or {}
    args = tool.get("arguments") or {}
    cmd = " ".join(str(v) for v in args.values() if isinstance(v, (str, int)))
    op = str(res.get("operation", "")).lower()
    target = str(res.get("target", ""))
    renv = str(res.get("environment", "")).lower()
    sens = str(res.get("sensitivity", "")).lower()
    disposable = res.get("disposable") is True
    dest = str(res.get("destination", res.get("destinationEnvironment", "")) or "").lower()

    destructive = op in DESTRUCTIVE_OPS or bool(CMD_DESTRUCT.search(cmd))
    exfil = (op in EXFIL_OPS or bool(CMD_EXFIL.search(cmd))
             or (dest and dest not in {"", "none", "local", "container", renv}))
    sensitive = sens in SENSITIVE or bool(CMD_CRED.search(cmd + " " + target))
    risky_env = renv in RISKY_ENVS or str(env.get("kind", "")).lower() in RISKY_ENVS
    sbox = sandboxed(env) and renv == "container"

    # does the user actually authorize this action on this target?
    ut = toks(all_user)
    action_t = toks(" ".join([op, target, cmd]))
    authorized = bool(ut & action_t) or bool(ut & toks(target.replace("/", " ")))
    explicit_target = bool(toks(target.replace("/", " ")) & ut) or target.lower() in all_user.lower()
    rollback = truthy_plan(case.get("rollbackPlan"))

    if req == "block":
        tdec = "block"
    elif injected and (destructive or exfil or sensitive) and not explicit_target:
        tdec = "block"
    elif exfil and (sensitive or not sbox):
        tdec = "block" if not explicit_target else "review"
    elif sensitive and not explicit_target:
        tdec = "block"
    elif destructive:
        if sbox and disposable and sens in {"public", ""} and authorized:
            tdec = "allow"
        elif not authorized:
            tdec = "block"
        elif rollback and not sensitive:
            tdec = "allow" if explicit_target else "review"
        else:
            tdec = "review"
    elif req == "review":
        tdec = "review"
    elif risky_env and op not in {"read", "list", "stat", "search", "get"}:
        tdec = "allow" if authorized and sens in {"public", ""} else "review"
    else:
        tdec = "allow" if (authorized or op in {"read", "list", "stat", "search", "get"}) else "review"

    # ---- route ----
    if req == "block":
        route = "none"
    elif req == "review" or tdec == "review":
        route = "restricted"
    else:
        route = "primary"

    # ---- trajectory (is the session heading outside its authorized scope?) ----
    if tdec == "block" and (injected or exfil or (sensitive and not explicit_target)):
        traj = "intervene"
    elif req == "block":
        traj = "intervene"
    elif injected or tdec in {"block", "review"}:
        traj = "watch"
    else:
        traj = "normal"
    return req, tdec, route, traj


@app.get("/classify")
def config():
    return jsonify({
        "profile": PROFILE,
        "method": "deterministic rules",
        "labels": {
            "requestDecision": ["allow", "block", "review"],
            "toolDecision": ["allow", "block", "review", "none"],
            "route": ["primary", "restricted", "none"],
            "trajectory": ["normal", "watch", "intervene"],
        },
    })


@app.post("/classify")
def run():
    body = request.get_json(force=True, silent=True) or {}
    print("REQ " + dump(body)[:200000], flush=True)
    try:
        with open(LOG, "a") as f:
            f.write(dump({"t": time.time(), "body": body}) + "\n")
    except Exception:
        pass
    results = []
    for case in body.get("cases") or []:
        cid = case.get("caseId")
        try:
            r, t, ro, tr = classify(case)
        except Exception:
            r, t, ro, tr = "review", ("review" if case.get("proposedTool") else "none"), "restricted", "watch"
        results.append({"caseId": cid, "requestDecision": r, "toolDecision": t, "route": ro, "trajectory": tr})
    return jsonify({"profile": body.get("profile", PROFILE), "batchId": body.get("batchId"), "results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

"""
ntfy push notifications for AirBnBrrr.

One alert event = ONE notification that lists every problem found on that AC
(hard-limit breaches, rule-engine findings and what the ML model found odd),
instead of one message per problem.

Configure with environment variables on Render:
    NTFY_TOPIC    required. Use a long random name, public topics are readable by anyone
                  who knows the name, e.g. AirBnrr_alien_test_code_k8x2m9qv4t
    NTFY_SERVER   optional, default https://ntfy.sh (set it if you self-host)
    NTFY_TOKEN    optional access token, for protected topics
    APP_URL       optional, your site address; tapping the notification opens the Alerts page
Uses only the standard library, so there is nothing new to install.
"""
import os
import urllib.request

from services import action_guide
from datetime import datetime, timedelta, timezone

LOCAL_TZ = timezone(timedelta(hours=8))
MAX_PROBLEMS = 12
MAX_BYTES = 3800  # ntfy limit is 4096


def finding_text(f):
    """One readable line for a rule-engine finding (dict with issue, sensor, severity, ...) or a plain string."""
    if isinstance(f, str):
        return f.strip()
    if isinstance(f, dict) and f.get("issue"):
        text = action_guide.short_name(f["issue"])
        if f.get("severity"):
            text = f"[{f['severity']}] {text}"
        val = action_guide.fmt_measured(f)
        if val:
            normal = f.get("normal_range")
            text += f": {val}" + (f" (normal {normal})" if normal else "")
        return text
    if isinstance(f, dict):
        for k in ("message", "finding", "text", "description", "reason", "rule"):
            if f.get(k):
                return str(f[k]).strip()
    return str(f)


_SEV = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def build_problems(critical_reasons, findings, ml):
    """The list of problems for one notification, worst first, no duplicates.

    The rule engine uses the same limits as the hard limits, so when it has findings the raw limit
    lines would only repeat them; they are used only when the rule engine found nothing.
    """
    ordered = sorted(findings or [], key=lambda f: -_SEV.get(f.get("severity") if isinstance(f, dict) else None, 0))
    items = [finding_text(f) for f in ordered] if ordered else list(critical_reasons or [])
    line = action_guide.ml_line(ml)
    if line:
        items.append(line)
    seen, out = set(), []
    for it in items:
        key = it.lower()
        if it and key not in seen:
            seen.add(key)
            out.append(it)
    return out


def _fmt(v, unit=""):
    try:
        return f"{float(v):g}{unit}"
    except (TypeError, ValueError):
        return None


def readings_line(r):
    parts = []
    volt, amp, watt = _fmt(r.get("pzem_voltage"), " V"), _fmt(r.get("pzem_current"), " A"), _fmt(r.get("pzem_power"), " W")
    if volt or amp or watt:
        parts.append(" | ".join(x for x in (volt, amp, watt) if x))
    t, h = _fmt(r.get("dht_temp"), " C"), _fmt(r.get("dht_humidity"), " %")
    if t or h:
        parts.append("room " + " / ".join(x for x in (t, h) if x))
    t1, t2 = _fmt(r.get("ds18b20_temp1")), _fmt(r.get("ds18b20_temp2"))
    if t1 or t2:
        parts.append("ds18b20 " + " / ".join(x for x in (t1, t2) if x) + " C")
    vib = _fmt(r.get("vibration"))
    if vib:
        parts.append("vibration " + vib)
    return "\n".join(parts)


def build_message(unit_title, is_critical, problems, readings, actions=None):
    """Return (title, body). Title is plain ASCII because it travels in an HTTP header."""
    level = "CRITICAL" if is_critical else "Warning"
    title = f"{level}: {unit_title}".encode("ascii", "replace").decode("ascii")
    lines = [f"{len(problems)} problem{'s' if len(problems) != 1 else ''} found:" if problems
             else "The AC is behaving abnormally."]
    shown = problems[:MAX_PROBLEMS]
    lines += [f"- {p}" for p in shown]
    if len(problems) > len(shown):
        lines.append(f"- ...and {len(problems) - len(shown)} more")
    if actions:
        lines += ["", "What to do now:"] + [f"{i}. {a}" for i, a in enumerate(actions, start=1)]
    rl = readings_line(readings or {})
    if rl:
        lines += ["", "Latest readings:", rl]
    lines += ["", datetime.now(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S")]
    body = "\n".join(lines)
    return title, body.encode("utf-8")[:MAX_BYTES].decode("utf-8", "ignore")


def _post(title, body, priority, tags):
    topic = os.environ.get("NTFY_TOPIC", "").strip()
    if not topic:
        print("[NTFY] NTFY_TOPIC is not set, skipping notification", flush=True)
        return False
    server = os.environ.get("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
    headers = {"Title": title, "Priority": str(priority), "Tags": tags}
    if os.environ.get("APP_URL"):
        headers["Click"] = os.environ["APP_URL"].rstrip("/") + "/pages/alerts"
    if os.environ.get("NTFY_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["NTFY_TOKEN"]
    req = urllib.request.Request(f"{server}/{topic}", data=body.encode("utf-8"), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            ok = 200 <= resp.status < 300
        print(f"[NTFY] sent '{title}'" if ok else f"[NTFY] unexpected status {resp.status}", flush=True)
        return ok
    except Exception as e:
        print(f"[NTFY] send failed: {e}", flush=True)
        return False


def send_alert(unit_title, is_critical, problems, readings, actions=None):
    title, body = build_message(unit_title, is_critical, problems, readings, actions)
    return _post(title, body, 5 if is_critical else 4, "rotating_light" if is_critical else "warning")


def send_test():
    return _post("AirBnBrrr test", "ntfy is connected. Real alerts will look like this, with every problem of an AC in one message.", 3, "white_check_mark")

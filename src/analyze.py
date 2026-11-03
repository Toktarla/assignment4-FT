from __future__ import annotations

from .dataset import load

ATTACK_STAGE = {
    "09:01": "credential attack",
    "09:03": "credential attack",
    "09:04": "privilege compromise",
    "09:07": "data destruction",
    "09:08": "data destruction",
    "09:10": "data destruction",
    "09:12": "recovery attack",
    "09:13": "exfiltration",
    "09:15": "exfiltration",
    "09:18": "persistence",
}

EVIDENCE = {
    "09:01": "15 failed logins from 10.20.4.15",
    "09:03": "21 more failures from the same IP",
    "09:04": "Login succeeded after 36 failures",
    "09:07": "320 research files changed in bulk",
    "09:08": "CPU 95% on Research-Server-01",
    "09:10": "1,200 files encrypted on the host",
    "09:12": "Delete attempt against the backup store",
    "09:13": "Egress from Research-Server-01 to unknown IP",
    "09:15": "Sudden jump in database queries",
    "09:18": "Antivirus service stopped on the host",
}

THREATS = [
    {
        "threat": "Credential compromise",
        "likelihood": 5,
        "impact": 4,
        "reason": "36 failed logins then a success from 10.20.4.15. No MFA on the baseline host, so this is treated as almost certain.",
    },
    {
        "threat": "Ransomware",
        "likelihood": 5,
        "impact": 5,
        "reason": "1,200 files were encrypted and CPU hit 95%. Impact is total loss of the working research set if restore fails.",
    },
    {
        "threat": "Backup destruction",
        "likelihood": 4,
        "impact": 5,
        "reason": "A delete attempt is in the log. It did not have to succeed to show intent. If it had worked, RPO/RTO would be meaningless.",
    },
    {
        "threat": "Data exfiltration",
        "likelihood": 4,
        "impact": 4,
        "reason": "Unknown outbound IP plus a database spike. Volume is not proven, so impact stays at 4 rather than 5.",
    },
    {
        "threat": "Privilege escalation",
        "likelihood": 4,
        "impact": 4,
        "reason": "Disabling antivirus needs local admin or equivalent. That is enough to keep persistence, not by itself the data-loss event.",
    },
]


def risk_band(score: int) -> str:
    if score <= 4:
        return "Low"
    if score <= 9:
        return "Medium"
    if score <= 16:
        return "High"
    return "Critical"


def part_a() -> list[dict]:
    data = load()
    rows = []
    for event in data["events"]:
        t = event["time"]
        rows.append(
            {
                "time": t,
                "event": event["event"],
                "attack_stage": ATTACK_STAGE[t],
                "evidence": EVIDENCE[t],
                "risk": event["severity"],
            }
        )
    return rows


def part_b() -> list[dict]:
    rows = []
    for item in THREATS:
        score = item["likelihood"] * item["impact"]
        rows.append(
            {
                "threat": item["threat"],
                "likelihood": item["likelihood"],
                "impact": item["impact"],
                "risk_score": score,
                "priority": risk_band(score),
                "reason": item["reason"],
            }
        )
    rows.sort(key=lambda r: (-r["risk_score"], -r["impact"]))
    for i, row in enumerate(rows, start=1):
        row["rank"] = i
        row["priority_label"] = f"P{i} {row['priority']}"
    return rows


def part_e() -> dict:
    data = load()
    threshold = data["requirements"]["anomaly_threshold"]
    scores = data["anomaly_scores"]
    flagged = [s for s in scores if s["observed"] >= threshold]
    ranked = sorted(scores, key=lambda s: s["observed"], reverse=True)
    with_delta = [
        {
            **s,
            "delta": round(s["observed"] - s["normal"], 2),
            "ratio": round(s["observed"] / s["normal"], 2),
            "anomaly": s["observed"] >= threshold,
        }
        for s in scores
    ]
    return {
        "threshold": threshold,
        "total": len(scores),
        "anomalies": len(flagged),
        "rate": len(flagged) / len(scores),
        "highest": ranked[0],
        "scores": with_delta,
    }

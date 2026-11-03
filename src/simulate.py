from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field

from .analyze import ATTACK_STAGE
from .dataset import load

SNAPSHOT_MINUTES = (0, 5, 10, 15, 20)
LOCKOUT_AFTER = 5
DATA_GB = 180.0
RESTORE_GB_PER_MIN = 20.0
VERIFY_MIN = 4.0
FAILOVER_MIN = 3.0
EVIDENCE_MIN = 4.0
BACKUP_ACTIVATE_MIN = 2.0
ISOLATE_MIN = 2.0
DETECT_MIN = 1.0


@dataclass
class Controls:
    name: str
    mfa: bool
    lockout_after: int | None
    segmentation: bool
    immutable_backup: bool
    ids: bool
    auto_isolate: bool
    egress_filter: bool
    edr_tamper_protect: bool
    stolen_session: bool = False


@dataclass
class State:
    session: bool = False
    failed: int = 0
    locked: bool = False
    isolated: bool = False
    files_modified: int = 0
    files_encrypted: int = 0
    cpu: float = 0.18
    backup_intact: bool = True
    backup_delete_blocked: bool = False
    outbound: list[str] = field(default_factory=list)
    db_requests: int = 0
    av_enabled: bool = True
    alerts: list[str] = field(default_factory=list)
    blocked: list[dict] = field(default_factory=list)
    applied: list[dict] = field(default_factory=list)
    isolated_at: float | None = None
    detected_at: float | None = None


def controls_for(mode: str) -> Controls:
    if mode == "baseline":
        return Controls(
            name="baseline",
            mfa=False,
            lockout_after=None,
            segmentation=False,
            immutable_backup=False,
            ids=False,
            auto_isolate=False,
            egress_filter=False,
            edr_tamper_protect=False,
        )
    if mode == "hardened":
        return Controls(
            name="hardened",
            mfa=True,
            lockout_after=LOCKOUT_AFTER,
            segmentation=True,
            immutable_backup=True,
            ids=True,
            auto_isolate=True,
            egress_filter=True,
            edr_tamper_protect=True,
        )
    if mode == "stolen_session":
        return Controls(
            name="stolen_session",
            mfa=True,
            lockout_after=LOCKOUT_AFTER,
            segmentation=True,
            immutable_backup=True,
            ids=True,
            auto_isolate=True,
            egress_filter=True,
            edr_tamper_protect=True,
            stolen_session=True,
        )
    raise ValueError(mode)


def _block(state: State, event: dict, reason: str) -> None:
    state.blocked.append({"time": event["time"], "event": event["event"], "reason": reason})


def _apply(state: State, event: dict, note: str) -> None:
    state.applied.append({"time": event["time"], "event": event["event"], "note": note})


def _maybe_detect(state: State, ctrl: Controls, minute: float, reason: str) -> None:
    if not ctrl.ids:
        return
    if state.detected_at is None:
        state.detected_at = minute
        state.alerts.append(reason)
    elif reason not in state.alerts:
        state.alerts.append(reason)


def _maybe_isolate(state: State, ctrl: Controls, minute: float) -> None:
    if ctrl.auto_isolate and state.detected_at is not None and not state.isolated:
        state.isolated = True
        state.isolated_at = minute
        state.session = False


def play(mode: str) -> dict:
    data = load()
    ctrl = controls_for(mode)
    state = State()

    for event in data["events"]:
        t = event["time"]
        minute = float(event["minute"])
        name = event["event"]

        if name.endswith("failed logins"):
            n = int(event["failed_logins"])
            state.failed += n
            if ctrl.lockout_after is not None and state.failed >= ctrl.lockout_after:
                state.locked = True
                _maybe_detect(state, ctrl, minute, "brute-force lockout")
                _block(event=event, state=state, reason=f"account locked after {ctrl.lockout_after} failures")
            else:
                _apply(state, event, f"{n} failures counted")
            continue

        if name == "Successful login":
            if ctrl.stolen_session:
                state.session = True
                state.locked = False
                _apply(state, event, "phished MFA session accepted")
                _maybe_detect(state, ctrl, minute, "login after brute-force source")
                continue
            if state.locked:
                _block(state, event, "account is locked")
                continue
            if ctrl.mfa:
                _block(state, event, "MFA challenge failed")
                _maybe_detect(state, ctrl, minute, "MFA rejection after brute force")
                continue
            state.session = True
            _apply(state, event, "password-only login accepted")
            continue

        if not state.session and not state.isolated:
            _block(state, event, "no session on the host")
            continue

        if name == "320 files modified":
            if state.isolated:
                _block(state, event, "host already isolated")
                continue
            state.files_modified = int(event["files_modified"])
            _apply(state, event, "bulk file changes")
            _maybe_detect(state, ctrl, minute, "file-modification burst")
            _maybe_isolate(state, ctrl, minute)
            continue

        if name.startswith("CPU usage"):
            if state.isolated and ctrl.edr_tamper_protect:
                state.cpu = 0.22
                _block(state, event, "EDR stopped the encryptor")
                continue
            state.cpu = float(event["cpu"])
            _apply(state, event, "encryptor running")
            continue

        if "encrypted" in name:
            if state.isolated and ctrl.edr_tamper_protect:
                _block(state, event, "encryption halted after isolate")
                continue
            state.files_encrypted = int(event["files_encrypted"])
            _apply(state, event, "mass encryption")
            _maybe_detect(state, ctrl, minute, "ransomware encryption")
            _maybe_isolate(state, ctrl, minute)
            continue

        if name == "Backup deletion attempt":
            if ctrl.immutable_backup or ctrl.segmentation or state.isolated:
                state.backup_delete_blocked = True
                reasons = []
                if state.isolated:
                    reasons.append("host isolated")
                if ctrl.segmentation:
                    reasons.append("backup VLAN unreachable")
                if ctrl.immutable_backup:
                    reasons.append("object lock denies delete")
                _block(state, event, "; ".join(reasons))
                _maybe_detect(state, ctrl, minute, "backup delete attempt")
                continue
            state.backup_intact = False
            _apply(state, event, "backup store deleted")
            continue

        if name.startswith("Outbound connection"):
            dest = event.get("destination", "unknown")
            if state.isolated or ctrl.egress_filter:
                reason = "egress filter" if ctrl.egress_filter else "host isolated"
                _block(state, event, f"{reason}, dest {dest}")
                _maybe_detect(state, ctrl, minute, "unknown egress")
                continue
            state.outbound.append(dest)
            _apply(state, event, f"connected to {dest}")
            continue

        if name == "Database access spike":
            if state.isolated or ctrl.segmentation:
                _block(state, event, "database subnet unreachable")
                continue
            state.db_requests = int(event["db_requests"])
            _apply(state, event, "database dump traffic")
            continue

        if name == "Antivirus disabled":
            if state.isolated or ctrl.edr_tamper_protect:
                _block(state, event, "EDR tamper protection")
                continue
            state.av_enabled = False
            _apply(state, event, "AV service stopped")
            continue

        _apply(state, event, ATTACK_STAGE[t])

    recovery = recovery_plan(state, ctrl, data["requirements"])
    return {
        "mode": mode,
        "controls": ctrl.__dict__,
        "session": state.session,
        "locked": state.locked,
        "isolated": state.isolated,
        "isolated_at": state.isolated_at,
        "detected_at": state.detected_at,
        "files_modified": state.files_modified,
        "files_encrypted": state.files_encrypted,
        "cpu": state.cpu,
        "backup_intact": state.backup_intact,
        "backup_delete_blocked": state.backup_delete_blocked,
        "outbound": list(state.outbound),
        "db_requests": state.db_requests,
        "av_enabled": state.av_enabled,
        "alerts": list(state.alerts),
        "blocked": deepcopy(state.blocked),
        "applied": deepcopy(state.applied),
        "recovery": recovery,
    }


def last_clean_snapshot() -> int:
    destructive = 7.0
    clean = [m for m in SNAPSHOT_MINUTES if m < destructive]
    return max(clean)


def recovery_plan(state: State, ctrl: Controls, requirements: dict) -> dict:
    rpo_limit = requirements["rpo_minutes"]
    rto_limit = requirements["rto_minutes"]

    if not state.backup_intact:
        steps = _steps(None)
        return {
            "possible": False,
            "reason": "backup was destroyed",
            "rpo_minutes": None,
            "rto_minutes": None,
            "rpo_met": False,
            "rto_met": False,
            "rpo_limit": rpo_limit,
            "rto_limit": rto_limit,
            "last_clean_snapshot": None,
            "steps": steps,
        }

    if ctrl.name == "hardened" and not state.session and state.files_modified == 0:
        steps = [
            {"step": 1, "action": "Detect incident", "component": "IDS / SIEM", "target_min": 1.0, "actual_min": 1.0},
            {"step": 2, "action": "Isolate affected system", "component": "Account lockout + firewall", "target_min": 2.0, "actual_min": 1.0},
            {"step": 3, "action": "Preserve evidence", "component": "Auth and IDS logs", "target_min": 5.0, "actual_min": 2.0},
            {"step": 4, "action": "Activate backup", "component": "Immutable vault", "target_min": 2.0, "actual_min": 0.0},
            {"step": 5, "action": "Restore services", "component": "Recovery environment", "target_min": 12.0, "actual_min": 0.0},
            {"step": 6, "action": "Verify integrity", "component": "Monitoring", "target_min": 5.0, "actual_min": 1.0},
            {"step": 7, "action": "Return to production", "component": "No failover required", "target_min": 3.0, "actual_min": 0.0},
        ]
        rto = round(sum(s["actual_min"] for s in steps), 1)
        return {
            "possible": True,
            "reason": "MFA and lockout stopped the login. No restore needed.",
            "rpo_minutes": 0.0,
            "rto_minutes": rto,
            "rpo_met": True,
            "rto_met": rto <= rto_limit,
            "rpo_limit": rpo_limit,
            "rto_limit": rto_limit,
            "last_clean_snapshot": "09:00",
            "steps": steps,
        }

    snap = last_clean_snapshot()
    rpo = max(0.0, 7.0 - snap)
    restore_min = round(DATA_GB / RESTORE_GB_PER_MIN, 1)
    detect_actual = DETECT_MIN if ctrl.ids else 8.0
    isolate_actual = ISOLATE_MIN if ctrl.auto_isolate else 10.0
    steps = [
        {"step": 1, "action": "Detect incident", "component": "IDS / SIEM + EDR", "target_min": 1.0, "actual_min": detect_actual},
        {"step": 2, "action": "Isolate affected system", "component": "Segmentation / firewall", "target_min": 2.0, "actual_min": isolate_actual},
        {"step": 3, "action": "Preserve evidence", "component": "Forensic snapshot", "target_min": 5.0, "actual_min": EVIDENCE_MIN},
        {"step": 4, "action": "Activate backup", "component": "Immutable vault", "target_min": 2.0, "actual_min": BACKUP_ACTIVATE_MIN},
        {"step": 5, "action": "Restore services", "component": "Recovery environment", "target_min": 12.0, "actual_min": restore_min},
        {"step": 6, "action": "Verify integrity", "component": "Checksums + monitoring", "target_min": 5.0, "actual_min": VERIFY_MIN},
        {"step": 7, "action": "Return to production", "component": "Secure failover", "target_min": 3.0, "actual_min": FAILOVER_MIN},
    ]
    rto = round(sum(s["actual_min"] for s in steps), 1)
    return {
        "possible": True,
        "reason": f"Restore from snapshot 09:{snap:02d} into the recovery VLAN.",
        "rpo_minutes": rpo,
        "rto_minutes": rto,
        "rpo_met": rpo <= rpo_limit,
        "rto_met": rto <= rto_limit,
        "rpo_limit": rpo_limit,
        "rto_limit": rto_limit,
        "last_clean_snapshot": f"09:{snap:02d}",
        "steps": steps,
    }


def _steps(unused: None) -> list[dict]:
    return [
        {"step": 1, "action": "Detect incident", "component": "IDS / SIEM + EDR", "target_min": 1.0, "actual_min": None},
        {"step": 2, "action": "Isolate affected system", "component": "Segmentation / firewall", "target_min": 2.0, "actual_min": None},
        {"step": 3, "action": "Preserve evidence", "component": "Forensic snapshot", "target_min": 5.0, "actual_min": None},
        {"step": 4, "action": "Activate backup", "component": "Immutable vault", "target_min": 2.0, "actual_min": None},
        {"step": 5, "action": "Restore services", "component": "Recovery environment", "target_min": 12.0, "actual_min": None},
        {"step": 6, "action": "Verify integrity", "component": "Checksums + monitoring", "target_min": 5.0, "actual_min": None},
        {"step": 7, "action": "Return to production", "component": "Secure failover", "target_min": 3.0, "actual_min": None},
    ]


def architecture_controls() -> list[dict]:
    return [
        {
            "threat": "Credential attack",
            "preventive": "MFA (NCA RK / TOTP) + lockout after 5 failures",
            "detection": "SIEM correlation of failed logins from 10.20.4.15",
            "recovery": "Revoke sessions, reset password, keep account locked",
        },
        {
            "threat": "Ransomware",
            "preventive": "Least privilege, allow-listing, research VLAN only",
            "detection": "EDR + IDS on file-entropy and CPU burst",
            "recovery": "Isolate host, restore 09:05 snapshot in recovery VLAN",
        },
        {
            "threat": "Backup deletion",
            "preventive": "Immutable object lock, backup VLAN, separate IAM",
            "detection": "Alert on delete API to the vault",
            "recovery": "Ignore the delete; restore from locked snapshot",
        },
        {
            "threat": "Data exfiltration",
            "preventive": "Egress allow-list, no direct internet from research VLAN",
            "detection": "Netflow / IDS on unknown destinations",
            "recovery": "Drop the flow, rotate keys, check DLP logs",
        },
        {
            "threat": "Privilege escalation",
            "preventive": "No local admin, EDR tamper protection",
            "detection": "EDR alert if AV or EDR is stopped",
            "recovery": "Rebuild from gold image, do not trust the old host",
        },
    ]


def run_all() -> dict:
    return {
        "baseline": play("baseline"),
        "hardened": play("hardened"),
        "stolen_session": play("stolen_session"),
    }

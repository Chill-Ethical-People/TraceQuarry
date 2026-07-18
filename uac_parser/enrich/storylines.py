from __future__ import annotations

from collections import defaultdict

from uac_parser.timeline.event import TimelineEvent


def build_storylines(events: list[TimelineEvent]) -> list[dict[str, object]]:
    ordered = [e for e in events if e.timestamp]
    storylines: list[dict[str, object]] = []
    for idx, event in enumerate(ordered):
        if event.event_action not in {"ssh_login_success", "http_request"}:
            continue
        window = ordered[idx: idx + 25]
        actions = {e.event_action for e in window}
        for window_event in window:
            actions.update(window_event.detection_names)
        if {"download_execute_chain", "cron_modified"} & actions or {"chmod_executable", "miner_execution"} <= actions:
            storylines.append({
                "title": "Initial access followed by suspicious execution or persistence",
                "start": event.timestamp,
                "end": window[-1].timestamp,
                "confidence": "medium",
                "event_ids": [e.event_id for e in window if e.severity in {"medium", "high", "critical"}][:15],
                "summary": "A login or web request is followed by high-signal Linux attack behaviors.",
            })
    storylines.extend(_bruteforce_to_access_storylines(ordered))
    storylines.extend(_credential_change_storylines(ordered))
    return storylines


def _bruteforce_to_access_storylines(ordered: list[TimelineEvent]) -> list[dict[str, object]]:
    storylines: list[dict[str, object]] = []
    by_src: dict[str | None, list[TimelineEvent]] = defaultdict(list)
    successes_by_src: dict[str | None, list[TimelineEvent]] = defaultdict(list)
    for event in ordered:
        if event.event_action == "ssh_login_failure":
            by_src[event.src_ip].append(event)
        elif event.event_action == "ssh_login_success":
            successes_by_src[event.src_ip].append(event)
    for src_ip, failures in by_src.items():
        if len(failures) < 10:
            continue
        successes = successes_by_src.get(src_ip, [])
        if not successes:
            continue
        first_fail = min((e.timestamp for e in failures if e.timestamp), default="")
        for success in successes:
            if not success.timestamp:
                continue
            prior = [f for f in failures if f.timestamp and f.timestamp <= success.timestamp]
            if len(prior) < 5:
                continue
            post_events = [
                e for e in ordered
                if e.timestamp and e.timestamp >= success.timestamp
                and e.event_action in {
                    "sudo_command", "shell_command", "password_changed",
                    "user_created", "user_modified", "account_unlocked",
                }
            ][:10]
            all_events = prior[-3:] + [success] + post_events
            storylines.append({
                "title": f"Brute-force from {src_ip} followed by successful login as {success.user}",
                "start": first_fail,
                "end": all_events[-1].timestamp if all_events else success.timestamp,
                "confidence": "high",
                "event_ids": [e.event_id for e in all_events if e.event_id][:15],
                "summary": (
                    f"{len(prior)} failed attempts from {src_ip} preceded a successful "
                    f"{success.user} login. {len(post_events)} post-access events followed."
                ),
            })
            break
    return storylines


def _credential_change_storylines(ordered: list[TimelineEvent]) -> list[dict[str, object]]:
    storylines: list[dict[str, object]] = []
    cred_events = [
        e for e in ordered
        if e.event_action in {"password_changed", "account_unlocked", "password_set_new_account"}
        or "root_password_changed" in e.detection_names
    ]
    if not cred_events:
        return []
    first = cred_events[0]
    last = cred_events[-1]
    users = sorted({e.user for e in cred_events if e.user})
    storylines.append({
        "title": "Credential modification activity",
        "start": first.timestamp,
        "end": last.timestamp,
        "confidence": "medium",
        "event_ids": [e.event_id for e in cred_events[:15]],
        "summary": (
            f"{len(cred_events)} credential change(s) detected for user(s): {', '.join(users)}. "
            f"Review whether these changes were authorized."
        ),
    })
    return storylines

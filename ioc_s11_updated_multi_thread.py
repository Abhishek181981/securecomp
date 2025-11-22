from __future__ import annotations

import os
import csv
import json
import re
import html
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any

import tkinter as tk
from tkinter import (
    Tk, Text, END, RIGHT, Y, LEFT, BOTH, Toplevel, Menu, messagebox, simpledialog,
)
from tkinter import ttk, filedialog

from paramiko.ssh_exception import SSHException
from netmiko import (
    ConnectHandler,
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
)
import pandas as pd

# ========= Timestamp helper =========

def now_ts() -> str:
    """Return current local timestamp suitable for logs/reports."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ========= Optional theming (ttkbootstrap) =========

_USE_BOOTSTRAP = True
try:
    import ttkbootstrap as tb
    from ttkbootstrap.constants import *  # noqa: F401,F403
except Exception:
    _USE_BOOTSTRAP = False

# ========= Config files & settings =========

FW_CSV = "firewalls.csv"  # default; not modified by the program
MASTER_IOC = "master_ioc.csv"  # append-only ledger of IOCs pushed
SETTINGS_FILE = "settings.json"  # persists last selected firewalls.csv


def load_settings() -> dict:
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(settings: dict) -> None:
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception:
        pass


_app_settings = load_settings()
current_fw_csv = _app_settings.get("last_firewalls_csv", FW_CSV)

# ========= Global & tunables =========

cancel_event = threading.Event()
DEFAULT_MAX_WORKERS = 6
ACCENT_HEX = "#2563EB"  # Fluent-ish blue

# ========= UI-safe helper calls =========

def ui_log(line: str) -> None:
    def _do():
        log_text.configure(state="normal")
        log_text.insert(END, f"[{now_ts()}] {line.rstrip()}\n")
        log_text.see(END)
        log_text.configure(state="disabled")
    root.after(0, _do)


def ui_status(text: str) -> None:
    root.after(0, lambda: status_label.config(text=text))


def ui_overall_progress(maximum: Optional[int] = None, value: Optional[int] = None) -> None:
    def _do():
        if maximum is not None:
            overall_progress.config(maximum=max(1, maximum))
        if value is not None:
            now_max = overall_progress["maximum"]
            overall_progress["value"] = max(0, min(now_max, value))
    root.after(0, _do)


def ui_device_progress(
    maximum: Optional[int] = None,
    value: Optional[int] = None,
    label: Optional[str] = None,
) -> None:
    def _do():
        if maximum is not None:
            device_progress.config(maximum=max(1, maximum))
        if value is not None:
            now_max = device_progress["maximum"]
            device_progress["value"] = max(0, min(now_max, value))
        if label is not None:
            device_label.configure(text=label)
    root.after(0, _do)


def ui_update_badges(succ: int, fa: int, ft: int, fo: int, sk: int) -> None:
    def _do():
        badge_success.config(text=f"Success {succ}")
        badge_auth.config(text=f"Auth {fa}")
        badge_timeout.config(text=f"Timeout {ft}")
        badge_other.config(text=f"Other {fo}")
        badge_skipped.config(text=f"Skipped {sk}")
    root.after(0, _do)


def ui_add_row(row: dict) -> None:
    def _do():
        results_tree.insert(
            "",
            END,
            values=(
                row.get("timestamp", ""),
                row.get("firewall_name", ""),
                row.get("ip", ""),
                row.get("platform", ""),
                row.get("status_code", ""),
                row.get("status_text", ""),
            ),
        )
    root.after(0, _do)


def toast(msg: str, ms: int = 2000) -> None:
    def _do():
        top = Toplevel(root)
        top.overrideredirect(True)
        top.attributes("-topmost", True)
        bg, fg = "#111827", "#F9FAFB"
        top.configure(bg=bg)
        ttk.Label(top, text=msg, background=bg, foreground=fg).pack(padx=14, pady=8)
        try:
            root.update_idletasks()
            x = root.winfo_rootx() + root.winfo_width() - 320
            y = root.winfo_rooty() + root.winfo_height() - 120
            top.geometry(f"+{x}+{y}")
        except Exception:
            pass
        top.after(ms, top.destroy)
    root.after(0, _do)

# ========= Validation & reporting =========

def is_valid_ip(ip: str) -> bool:
    ip = str(ip).strip()
    if not ip or ip == "0.0.0.0":
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def append_master_log(ioc_ips: List[str]) -> Tuple[bool, str]:
    try:
        os.makedirs(os.path.dirname(MASTER_IOC) or ".", exist_ok=True)
        ts = now_ts()
        with open(MASTER_IOC, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            for ip in ioc_ips:
                w.writerow([ts, ip])
        return True, "IOC entries appended to master_ioc.csv"
    except Exception as e:
        return False, f"Could not append to {MASTER_IOC}: {e}"


def make_run_report_path(prefix: str = "firewalls_status") -> str:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs("reports", exist_ok=True)
    return os.path.join("reports", f"{prefix}_{ts}.csv")


def write_status_report(rows: List[Dict[str, Any]], path: str) -> None:
    cols = [
        "timestamp",
        "firewall_name",
        "ip",
        "platform",
        "port",
        "status_text",
        "status_code",
        "ha_reason",
        "commands",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in cols})


def append_failures_ledger(
    rows: List[Dict[str, Any]],
    ledger_path=os.path.join("reports", "firewalls_failures.csv"),
) -> None:
    fail_rows = [r for r in rows if str(r.get("status_code", "")).startswith("failed")]
    if not fail_rows:
        return
    cols = [
        "timestamp",
        "firewall_name",
        "ip",
        "platform",
        "port",
        "status_text",
        "status_code",
        "ha_reason",
        "commands",
    ]
    os.makedirs(os.path.dirname(ledger_path) or ".", exist_ok=True)
    exists = os.path.exists(ledger_path)
    with open(ledger_path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        if not exists:
            w.writeheader()
        ts = now_ts()
        for r in fail_rows:
            w.writerow({
                "timestamp": ts,
                "firewall_name": r.get("firewall_name", ""),
                "ip": r.get("ip", ""),
                "platform": r.get("platform", ""),
                "port": r.get("port", ""),
                "status_text": r.get("status_text", ""),
                "status_code": r.get("status_code", ""),
                "ha_reason": r.get("ha_reason", ""),
                "commands": r.get("commands", ""),
            })

# ========= Netmiko compatibility =========

def connect_compat(params: Dict[str, Any]) -> Any:
    try:
        return ConnectHandler(**params)
    except TypeError as e:
        msg = str(e)
        p = dict(params)
        if "ssh_strict" in msg:
            p.pop("ssh_strict", None)
            p.setdefault("system_host_keys", False)
            p.setdefault("alt_host_keys", False)
        return ConnectHandler(**p)

# ========= Helpers for ASA =========

def _normalize_platform(value: str) -> str:
    s = html.unescape(str(value)).replace('\xa0', ' ')
    s = re.sub(r"\s+", " ", s).strip().lower()
    first = s.split(" ")[0] if s else ""
    return first


def _asa_switch_context(conn: Any, ctx_name: str) -> Optional[str]:
    ctx_name = str(ctx_name or "").strip()
    if not ctx_name:
        return None
    try:
        out = conn.send_command_timing(f"changeto context {ctx_name}")
        return out
    except Exception:
        return None


def _asa_verify_group(conn: Any, ioc_ips: List[str]) -> int:
    try:
        out = conn.send_command("show run object-group id GENERAL_IOC", read_timeout=20)
    except Exception:
        return 0
    found = 0
    for ip in ioc_ips:
        if f"network-object host {ip}" in out:
            found += 1
    return found

# ========= SRX helpers =========

def host_prefix(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
        return f"{ip}/32" if a.version == 4 else f"{ip}/128"
    except ValueError:
        return ip

# ========= Core push =========

def push_to_one_firewall(
    fw_row: Dict[str, Any],
    ioc_ips: List[str],
    creds: Dict[str, str],
    per_ip_progress_cb=None,
):
    fw_name = str(fw_row.get('firewall_name', '')).strip()
    fw_ip = str(fw_row.get('ip', '')).strip()
    platform_raw = _normalize_platform(str(fw_row.get('platform', '')))
    if platform_raw in {'panos', 'paloalto', 'palo_alto', 'pa'}:
        platform = 'panos'
    elif platform_raw == 'asa':
        platform = 'asa'
    elif platform_raw in {'srx', 'junos', 'juniper'}:
        platform = 'srx'
    else:
        platform = platform_raw

    ctx_name = str(fw_row.get('context', '')).strip()
    vsys = (str(fw_row.get('vsys', 'vsys1')).strip() or 'vsys1')
    port_raw = fw_row.get('port', 22)
    port = int(port_raw) if str(port_raw).strip() else 22
    lsys = str(fw_row.get('logical_system', '') or fw_row.get('lsys', '')).strip()

    name_disp = fw_name or fw_ip or '?'
    if not fw_ip or not platform:
        return name_disp, 'Skipped (missing ip/platform)', 'skipped', 'missing ip/platform', {}
    if platform not in ('asa', 'srx', 'panos'):
        return (
            name_disp,
            f'Skipped (unknown platform {platform_raw})',
            'skipped',
            f'unknown platform {platform_raw}',
            {},
        )
    if cancel_event.is_set():
        return name_disp, 'Cancelled', 'cancelled', 'cancel requested', {}

    device_type = (
        'cisco_asa' if platform == 'asa' else 'juniper_junos' if platform == 'srx' else 'paloalto_panos'
    )

    os.makedirs('logs', exist_ok=True)
    session_log = os.path.join('logs', f"{(fw_name or fw_ip).replace(' ', '_')}_{fw_ip}.log")

    params = {
        'device_type': device_type,
        'ip': fw_ip,
        'port': port,
        'username': creds['user'],
        'password': creds['pass'],
        'secret': creds.get('enable', ''),
        'timeout': 50,
        'banner_timeout': 50,
        'auth_timeout': 40,
        'global_delay_factor': 1.0,
        'allow_agent': False,
        'use_keys': False,
        'ssh_strict': False,
        'fast_cli': False,
        'session_log': session_log,
    }

    try:
        with connect_compat(params) as conn:
            ha_reason = 'HA check disabled'
            total_ip = len(ioc_ips)
            if per_ip_progress_cb:
                per_ip_progress_cb(0, total_ip, f'{name_disp}: connected; starting IOC updates')

            if platform == 'asa':
                try:
                    if not conn.check_enable_mode():
                        conn.enable()
                except Exception:
                    pass
                _asa_switch_context(conn, ctx_name)
                if ctx_name:
                    ui_log(f'{name_disp}: switched to ASA context {ctx_name}')
                try:
                    conn.send_command_timing('terminal pager 0')
                except Exception:
                    pass
                try:
                    out = conn.send_command('show run object-group id GENERAL_IOC', read_timeout=15)
                    if any(x in out.lower() for x in ['not found', 'error', 'invalid']):
                        conn.send_config_set(['object-group network GENERAL_IOC'], cmd_verify=False)
                except Exception:
                    try:
                        conn.send_config_set(['object-group network GENERAL_IOC'], cmd_verify=False)
                    except Exception:
                        pass
                error_seen = False
                done = 0
                for ip in ioc_ips:
                    if cancel_event.is_set():
                        return name_disp, 'Cancelled', 'cancelled', 'cancel requested', {}
                    cmds = ['object-group network GENERAL_IOC', f'network-object host {ip}']
                    try:
                        resp = conn.send_config_set(cmds, cmd_verify=False)
                        if any(e in resp.lower() for e in ['error', 'invalid', 'not permitted']):
                            error_seen = True
                    except Exception:
                        error_seen = True
                    done += 1
                    if per_ip_progress_cb:
                        per_ip_progress_cb(done, total_ip, f'{name_disp}: added {ip} ({done}/{total_ip})')
                present = _asa_verify_group(conn, ioc_ips)
                if present == total_ip and not error_seen:
                    return name_disp, 'Success', 'success', ha_reason, {}
                elif present > 0:
                    return name_disp, f'Partial success: {present}/{total_ip} entries present', 'failed_other', 'asa partial', {}
                else:
                    return name_disp, 'Failed (IOC not present)', 'failed_other', 'asa context/permission', {}

            elif platform == 'srx':
                srx_zones_raw = (
                    fw_row.get('zones', '')
                    or fw_row.get('srx_zones', '')
                    or fw_row.get('zone', '')
                )
                try:
                    import math
                    if isinstance(srx_zones_raw, float) and math.isnan(srx_zones_raw):
                        srx_zones_raw = ''
                except Exception:
                    pass
                srx_zones = [z.strip() for z in str(srx_zones_raw).split(',') if z.strip()]
                use_global = not srx_zones

                addr_names: List[str] = []
                cmd_preview = ''
                apply_errors = False

                try:
                    conn.config_mode()
                except Exception:
                    pass

                # If logical-system specified, move into it
                if lsys:
                    move = conn.send_command_timing(f'edit logical-systems {lsys}', strip_prompt=False, strip_command=False)
                    if 'error:' in str(move).lower():
                        return name_disp, f"Failed (logical-system '{lsys}' not found)", 'failed_other', 'SRX lsys missing', {'commands': cmd_preview}
                    cmd_preview += f"(context) edit logical-systems {lsys}\n"

                done = 0
                for ip in ioc_ips:
                    if cancel_event.is_set():
                        return name_disp, 'Cancelled', 'cancelled', 'cancel requested', {'commands': cmd_preview}
                    addr_name = f"IOC_{ip.replace('.', '_').replace(':', '_')}"
                    addr_names.append(addr_name)
                    cmds: List[str] = []

                    if use_global:
                        cmds.append(f"set security address-book global address {addr_name} {host_prefix(ip)}")
                        cmds.append(f"set security address-book global address-set GENERAL_IOC address {addr_name}")
                    else:
                        for z in srx_zones:
                            cmds.append(f"set security zones security-zone {z} address-book address {addr_name} {host_prefix(ip)}")
                        for z in srx_zones:
                            cmds.append(f"set security zones security-zone {z} address-book address-set GENERAL_IOC address {addr_name}")

                    try:
                        resp = conn.send_config_set(cmds, cmd_verify=False, exit_config_mode=False)
                        low = str(resp).lower()
                        if any(k in low for k in ['error:', 'invalid', 'unknown command', 'syntax error']):
                            apply_errors = True
                    except Exception:
                        apply_errors = True

                    cmd_preview += f"\n{ip}:\n" + "\n".join(cmds) + "\n"
                    done += 1
                    if per_ip_progress_cb:
                        per_ip_progress_cb(done, total_ip, f"{name_disp}: pushed {addr_name} ({done}/{total_ip})")

                # Commit (optionally synchronize for HA)
                try:
                    if bool(_app_settings.get('srx_commit_synchronize', False)):
                        commit_out = conn.commit(cmd='commit synchronize')
                    else:
                        commit_out = conn.commit()
                except Exception as e:
                    return name_disp, f'Failed (commit error: {e})', 'failed_other', 'SRX commit error', {'commands': cmd_preview}

                try:
                    conn.exit_config_mode()
                except Exception:
                    pass

                commit_ok = any(s in str(commit_out).lower() for s in ['commit complete', 'commit succeeded'])
                if not commit_ok or apply_errors:
                    status_txt = 'Failed (apply/commit issue)'
                    if commit_out:
                        status_txt += f": {str(commit_out).strip()}"
                    return name_disp, status_txt, 'failed_other', 'SRX apply/commit', {'commands': cmd_preview}

                # ===== Verification: check whether objects exist at expected scope =====
                verify_ok = True
                if use_global:
                    show_out = conn.send_command("show configuration security address-book global | display set", read_timeout=20)
                    for n in addr_names:
                        if n not in show_out:
                            verify_ok = False
                            break
                else:
                    for z in srx_zones:
                        show_out = conn.send_command(f"show configuration security zones security-zone {z} address-book | display set", read_timeout=20)
                        for n in addr_names:
                            if n not in show_out:
                                verify_ok = False
                                break
                        if not verify_ok:
                            break

                if not verify_ok:
                    return name_disp, 'Failed (post-commit verify)', 'failed_other', 'SRX verify', {'commands': cmd_preview}

                src_col = (
                    'zones' if str(fw_row.get('zones', '')).strip() else (
                        'srx_zones' if str(fw_row.get('srx_zones', '')).strip() else (
                            'zone' if str(fw_row.get('zone', '')).strip() else 'none'
                        )
                    )
                )
                zone_info = ', '.join(srx_zones) if srx_zones else '(global only)'
                ioc_info = ', '.join(addr_names)
                msg = (
                    "SRX PUSH MODE:\n\n"
                    f"Zones source: {src_col}\n"
                    f"Zones used: {zone_info}\n\n"
                    f"IOC address objects created:\n{ioc_info}\n\n"
                    "GENERAL_IOC membership applied at the appropriate scope.\n\n"
                    "Commands executed (per IP):\n" + cmd_preview
                )
                root.after(0, lambda: show_srx_summary(msg))
                return name_disp, 'Success', 'success', ha_reason, {'commands': cmd_preview}

            else:  # PAN-OS
                try:
                    conn.send_config_set([f'set system setting target-vsys {vsys}'], cmd_verify=False)
                except Exception:
                    pass
                done = 0
                for ip in ioc_ips:
                    if cancel_event.is_set():
                        return name_disp, 'Cancelled', 'cancelled', 'cancel requested', {}
                    addr_name = f"IOC_{ip.replace('.', '_').replace(':', '_')}"
                    cmds = [
                        f'set address {addr_name} ip-netmask {ip}',
                        f'set address-group GENERAL_IOC static {addr_name}',
                    ]
                    try:
                        conn.send_config_set(cmds, cmd_verify=False)
                    except Exception:
                        pass
                    done += 1
                    if per_ip_progress_cb:
                        per_ip_progress_cb(done, total_ip, f'{name_disp}: added {ip} ({done}/{total_ip})')
                try:
                    conn.commit()
                except Exception:
                    return name_disp, 'Failed (commit error)', 'failed_other', 'PAN-OS commit error', {}
                return name_disp, 'Success', 'success', ha_reason, {}

    except NetmikoAuthenticationException as e:
        return name_disp, f'Failed (Auth: {e})', 'failed_auth', 'auth error', {}
    except NetmikoTimeoutException as e:
        return name_disp, f'Failed (Timeout: {e})', 'failed_timeout', 'timeout', {}
    except SSHException as e:
        return name_disp, f'Failed (SSH: {e})', 'failed_other', 'ssh error', {}
    except TypeError as e:
        return name_disp, f'Failed (Param: {e})', 'failed_other', 'param error', {}
    except Exception as e:
        return name_disp, f'Error ({e})', 'failed_other', 'exception', {}

# ========= Orchestration =========

def push_ioc(
    fw_user: str,
    fw_pass: str,
    enable_pass: str,
    pasted_iocs: List[str],
    root_ref: Any,
) -> None:
    try:
        csv_path = current_fw_csv or FW_CSV
        if not os.path.exists(csv_path):
            root_ref.after(0, lambda: messagebox.showerror("Error", f"'{csv_path}' not found."))
            return
        try:
            df_fw = pd.read_csv(csv_path)
        except Exception as e:
            root_ref.after(0, lambda: messagebox.showerror("Error", f"Failed to read '{csv_path}': {e}"))
            return
        total_fw = len(df_fw)
        if total_fw == 0:
            root_ref.after(0, lambda: messagebox.showwarning("Warning", "No firewalls in the selected CSV."))
            return
        if not pasted_iocs:
            root_ref.after(0, lambda: messagebox.showwarning("Warning", "No valid IOC IPs provided."))
            return

        ui_overall_progress(maximum=total_fw, value=0)

        def _spin_start():
            device_progress.configure(mode="indeterminate")
            device_progress.start(50)
        root.after(0, _spin_start)

        ui_device_progress(maximum=1, value=0, label="Preparing parallel run...")

        success_count = 0
        fail_auth_count = 0
        fail_timeout_count = 0
        fail_other_count = 0
        skipped_count = 0
        cancelled = False
        completed_fw = 0
        run_results: List[Dict[str, Any]] = []

        creds = {"user": fw_user, "pass": fw_pass, "enable": enable_pass or ""}
        max_workers = min(DEFAULT_MAX_WORKERS, total_fw) if total_fw > 0 else 1

        def _submit_one(row: pd.Series):
            fw_name = str(row.get("firewall_name", "")).strip()
            fw_ip = str(row.get("ip", "")).strip()
            name_disp = fw_name or fw_ip or "?"
            ui_log(f"Queueing {name_disp} ({fw_ip})")
            return push_to_one_firewall(row, pasted_iocs, creds, per_ip_progress_cb=None)

        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="fw") as tp:
            future_map = {tp.submit(_submit_one, fw_row): fw_row for _, fw_row in df_fw.iterrows()}

            def _spin_stop():
                device_progress.stop()
                device_progress.configure(mode="determinate")
                ui_device_progress(label=f"Parallel mode (workers {max_workers})")
            root.after(0, _spin_stop)

            for fut in as_completed(future_map):
                if cancel_event.is_set():
                    cancelled = True
                fw_row = future_map[fut]
                fw_name = str(fw_row.get("firewall_name", "")).strip()
                fw_ip = str(fw_row.get("ip", "")).strip()
                platform = str(fw_row.get("platform", "")).strip()
                port = fw_row.get("port", 22)
                try:
                    name, status_text, status_code, ha_reason, extra = fut.result()
                except Exception as e:
                    name, status_text, status_code, ha_reason, extra = (
                        fw_name or fw_ip or "?",
                        f"Error ({e})",
                        "failed_other",
                        "exception",
                        {},
                    )
                ui_log(f"{name}: {status_text}")
                row_ts = now_ts()
                run_results.append({
                    "timestamp": row_ts,
                    "firewall_name": fw_name,
                    "ip": fw_ip,
                    "platform": platform,
                    "port": port,
                    "status_text": status_text,
                    "status_code": status_code,
                    "ha_reason": ha_reason,
                    "commands": (extra.get("commands") if isinstance(extra, dict) else ""),
                })
                if status_code == "success":
                    success_count += 1
                elif status_code == "failed_auth":
                    fail_auth_count += 1
                elif status_code == "failed_timeout":
                    fail_timeout_count += 1
                elif status_code == "failed_other":
                    fail_other_count += 1
                elif status_code == "skipped":
                    skipped_count += 1
                elif status_code == "cancelled":
                    cancelled = True

                ui_update_badges(success_count, fail_auth_count, fail_timeout_count, fail_other_count, skipped_count)
                completed_fw += 1
                ui_overall_progress(value=completed_fw)
                ui_status(f"Processed {completed_fw}/{total_fw}: {name} → {status_text}")
                ui_add_row({
                    "timestamp": row_ts,
                    "firewall_name": fw_name,
                    "ip": fw_ip,
                    "platform": platform,
                    "status_code": status_code,
                    "status_text": status_text,
                })

        report_path = make_run_report_path()
        try:
            write_status_report(run_results, report_path)
            ui_log(f"Wrote run report: {report_path}")
            toast(f"Report written: {report_path}")
        except Exception as e:
            ui_log(f"Could not write run report: {e}")

        try:
            append_failures_ledger(run_results)
        except Exception as e:
            ui_log(f"Could not append failures ledger: {e}")

        scope_line = f"Scope (firewalls): {total_fw}"
        if cancelled:
            msg = (
                "IOC push was CANCELLED by user.\n"
                "Summary:\n"
                f"{scope_line}\n"
                f"Success: {success_count}\n"
                f"Auth Failures: {fail_auth_count}\n"
                f"Timeouts: {fail_timeout_count}\n"
                f"Other Failures: {fail_other_count}\n"
                f"Skipped: {skipped_count}\n"
                "No entries were appended to master_ioc.csv."
            )
            root_ref.after(0, lambda: messagebox.showwarning("IOC Blocker - Cancelled", msg))
            return

        if success_count == 0:
            msg = (
                "IOC push completed with NO SUCCESSFUL devices.\n"
                "Summary:\n"
                f"{scope_line}\n"
                f"Success: {success_count}\n"
                f"Auth Failures: {fail_auth_count}\n"
                f"Timeouts: {fail_timeout_count}\n"
                f"Other Failures: {fail_other_count}\n"
                f"Skipped: {skipped_count}\n"
                "No entries were appended to master_ioc.csv.\n"
                "Tip: verify credentials/connectivity or check logs/ for session details."
            )
            root_ref.after(0, lambda: messagebox.showerror("IOC Blocker - Failed", msg))
            return

        ok, note = append_master_log(pasted_iocs)
        final = (
            "IOC push completed.\n"
            "Summary:\n"
            f"{scope_line}\n"
            f"Success: {success_count}\n"
            f"Auth Failures: {fail_auth_count}\n"
            f"Timeouts: {fail_timeout_count}\n"
            f"Other Failures: {fail_other_count}\n"
            f"Skipped: {skipped_count}\n"
            f"{note}\n"
            f"Run report: {report_path}"
        )
        root_ref.after(0, lambda: messagebox.showinfo("IOC Blocker", final))
        toast("IOC push completed")

    except Exception as e:
        root_ref.after(0, lambda: messagebox.showerror("Error", f"Unexpected error: {str(e)}"))

# ===== Scrollable Popup for SRX Summary =====

def show_srx_summary(summary_text: str):
    top = Toplevel(root)
    top.title("SRX Push Summary")
    top.geometry("900x600")
    text_area = Text(top, wrap="word", font=("Consolas", 10))
    text_area.insert("1.0", summary_text)
    text_area.configure(state="disabled")
    text_area.pack(side="left", fill="both", expand=True)
    scroll = ttk.Scrollbar(top, orient="vertical", command=text_area.yview)
    scroll.pack(side="right", fill="y")
    text_area.configure(yscrollcommand=scroll.set)

# ========= Events =========

def start_push() -> None:
    raw = ioc_text.get("1.0", END)
    lines = [ln.strip() for ln in raw.splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    pasted_iocs: List[str] = []
    invalids: List[str] = []
    seen = set()
    for ln in lines:
        if is_valid_ip(ln):
            if ln not in seen:
                seen.add(ln)
                pasted_iocs.append(ln)
        else:
            invalids.append(ln)
    if invalids:
        preview = ", ".join(invalids[:20]) + ("..." if len(invalids) > 20 else "")
        messagebox.showwarning("Invalid IPs", "These entries are invalid and will be skipped:\n" + preview)

    fw_user = simpledialog.askstring("Credentials", "Enter firewall username:")
    fw_pass = simpledialog.askstring("Credentials", "Enter firewall password:", show="*")
    enable_pass = simpledialog.askstring("Credentials", "Enter enable password (ASA):", show="*")
    if not fw_user or not fw_pass:
        messagebox.showwarning("Warning", "Credentials not entered.")
        return

    cancel_event.clear()
    ui_overall_progress(maximum=1, value=0)
    ui_device_progress(maximum=1, value=0, label="")
    ui_status("Starting...")
    ui_log(f"Using firewalls CSV: {current_fw_csv or FW_CSV}")

    threading.Thread(
        target=push_ioc,
        args=(fw_user.strip(), fw_pass, enable_pass or "", pasted_iocs, root),
        daemon=True,
    ).start()


def cancel_run() -> None:
    cancel_event.set()
    ui_status("Cancelling... Please wait.")
    ui_log("Cancellation requested by user.")
    toast("Cancelling...")


def open_folder(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
        import subprocess
        import platform
        if platform.system() == "Windows":
            subprocess.Popen(f'explorer "{os.path.abspath(path)}"')
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", os.path.abspath(path)])
        else:
            subprocess.Popen(["xdg-open", os.path.abspath(path)])
    except Exception as e:
        toast(f"Cannot open folder: {e}")

# ========= Build UI (Modern) =========

if _USE_BOOTSTRAP:
    root = tb.Window(themename="flatly")
else:
    root = Tk()
root.title("IOC Blocker")
root.geometry("1040x800")

# App Bar
appbar = ttk.Frame(root)
appbar.pack(fill="x")

title_lbl = ttk.Label(appbar, text="SecurBlock-An IOC Blocker", font=("Segoe UI", 16, "bold"))
title_lbl.pack(side=LEFT, padx=16, pady=10)

appbar_right = ttk.Frame(appbar)
appbar_right.pack(side=RIGHT, padx=6, pady=10)

fw_path_var = tk.StringVar(value=current_fw_csv)

def browse_fw_csv():
    global current_fw_csv, _app_settings
    path = filedialog.askopenfilename(title="Select firewalls.csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if not path:
        return
    try:
        _ = pd.read_csv(path, nrows=3)
    except Exception as e:
        messagebox.showerror("Invalid CSV", f"Cannot read CSV:\n{e}")
        return
    current_fw_csv = path
    fw_path_var.set(current_fw_csv)
    _app_settings["last_firewalls_csv"] = current_fw_csv
    save_settings(_app_settings)
    toast("firewalls.csv path updated")

fw_path_entry = ttk.Entry(appbar_right, textvariable=fw_path_var, width=42)
fw_path_entry.configure(state="readonly")
fw_path_entry.pack(side=LEFT, padx=(0, 6))

btn_browse_fw = ttk.Button(appbar_right, text="Browse…", command=browse_fw_csv)
btn_browse_fw.pack(side=LEFT, padx=(0, 12))

btn_open_reports = ttk.Button(appbar_right, text="Open Reports", command=lambda: open_folder("reports"))
btn_open_logs = ttk.Button(appbar_right, text="Open Logs", command=lambda: open_folder("logs"))
btn_open_reports.pack(side=LEFT, padx=6)
btn_open_logs.pack(side=LEFT, padx=6)

# Notebook
notebook = ttk.Notebook(root)
notebook.pack(fill=BOTH, expand=True, padx=12, pady=12)

tab_run = ttk.Frame(notebook)
tab_results = ttk.Frame(notebook)
tab_logs = ttk.Frame(notebook)

notebook.add(tab_run, text="Run")
notebook.add(tab_results, text="Results")
notebook.add(tab_logs, text="Logs")

# Run tab
badges_row = ttk.Frame(tab_run)
badges_row.pack(fill="x", padx=8, pady=(6, 2))

def _badge(parent, text, bg="#E5E7EB", fg="#111827"):
    c = tk.Label(parent, text=text, bg=bg, fg=fg, padx=10, pady=3, font=("Segoe UI", 9))
    c.pack(side=LEFT, padx=4)
    return c

badge_success = _badge(badges_row, "Success 0", "#D1FAE5", "#065F46")
badge_auth = _badge(badges_row, "Auth 0", "#FEE2E2", "#7F1D1D")
badge_timeout = _badge(badges_row, "Timeout 0", "#FEF3C7", "#7C2D12")
badge_other = _badge(badges_row, "Other 0", "#EDE9FE", "#4C1D95")
badge_skipped = _badge(badges_row, "Skipped 0", "#E5E7EB", "#1F2937")

controls = ttk.Frame(tab_run)
controls.pack(fill="x", padx=8, pady=(6, 8))

btn_start = ttk.Button(controls, text="Push IOC to Firewalls", command=start_push)
btn_cancel = ttk.Button(controls, text="Cancel", command=cancel_run)
btn_start.pack(side=LEFT, padx=6)
btn_cancel.pack(side=LEFT, padx=6)

status_label = ttk.Label(tab_run, text="Idle", anchor="w")
status_label.pack(fill="x", padx=12)

prog_row = ttk.Frame(tab_run)
prog_row.pack(fill="x", padx=12, pady=(4, 4))

ttk.Label(prog_row, text="Overall Progress (firewalls):").pack(anchor="w")
overall_progress = ttk.Progressbar(prog_row, length=960, mode="determinate")
overall_progress.pack(fill="x", pady=(2, 8))

device_label = ttk.Label(prog_row, text="Current Device: —")
device_label.pack(anchor="w")

device_progress = ttk.Progressbar(prog_row, length=960, mode="determinate")
device_progress.pack(fill="x", pady=(2, 6))

ioc_frame = ttk.LabelFrame(tab_run, text="IOC IPs (one per line)")
ioc_frame.pack(fill=BOTH, expand=True, padx=12, pady=(6, 10))

ioc_text = Text(ioc_frame, height=10, wrap="none", font=("Consolas", 10))
ioc_text.pack(side=LEFT, fill=BOTH, expand=True)

ioc_scroll = ttk.Scrollbar(ioc_frame, orient="vertical", command=ioc_text.yview)
ioc_scroll.pack(side=RIGHT, fill=Y)
ioc_text.configure(yscrollcommand=ioc_scroll.set)

ioc_text.insert("1.0", "203.0.113.5\n198.51.100.10\n# One IP per line; lines starting with # are ignored")

# Results tab
res_top = ttk.Frame(tab_results)
res_top.pack(fill="x", padx=12, pady=(12, 6))

ttk.Label(res_top, text="Quick filter:").pack(side=LEFT)
filter_entry = ttk.Entry(res_top, width=30)
filter_entry.pack(side=LEFT, padx=8)


def apply_filter(*_):
    q = filter_entry.get().strip().lower()
    for iid in results_tree.get_children(""):
        results_tree.reattach(iid, "", "end")
    if q:
        for iid in list(results_tree.get_children("")):
            vals = results_tree.item(iid, "values")
            show = any(q in str(v).lower() for v in vals)
            if not show:
                results_tree.detach(iid)

filter_entry.bind("<KeyRelease>", apply_filter)

results_frame = ttk.Frame(tab_results)
results_frame.pack(fill=BOTH, expand=True, padx=12, pady=(0, 12))

cols = ("timestamp", "firewall_name", "ip", "platform", "status_code", "status_text")
results_tree = ttk.Treeview(results_frame, columns=cols, show="headings", height=14)
for c in cols:
    results_tree.heading(c, text=c.replace("_", " ").title())
results_tree.column("timestamp", width=150, anchor="w")
results_tree.column("firewall_name", width=160, anchor="w")
results_tree.column("ip", width=140, anchor="w")
results_tree.column("platform", width=120, anchor="w")
results_tree.column("status_code", width=120, anchor="w")
results_tree.column("status_text", width=520, anchor="w")
results_tree.pack(side=LEFT, fill=BOTH, expand=True)

results_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=results_tree.yview)
results_scroll.pack(side=RIGHT, fill=Y)
results_tree.configure(yscrollcommand=results_scroll.set)

# Logs tab
logs_top = ttk.Frame(tab_logs)
logs_top.pack(fill="x", padx=12, pady=(12, 4))

def copy_log_selection(_=None):
    try:
        text = log_text.get("sel.first", "sel.last")
    except Exception:
        text = log_text.get("1.0", END)
    root.clipboard_clear()
    root.clipboard_append(text.strip())
    toast("Log copied")

btn_copy_log = ttk.Button(logs_top, text="Copy Log", command=copy_log_selection)
btn_copy_log.pack(side=LEFT, padx=4)

log_frame = ttk.Frame(tab_logs)
log_frame.pack(fill=BOTH, expand=True, padx=12, pady=(4, 12))

log_text = Text(log_frame, height=24, wrap="none", font=("Consolas", 10))
log_text.pack(side=LEFT, fill=BOTH, expand=True)

log_scroll2 = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
log_scroll2.pack(side=RIGHT, fill=Y)
log_text.configure(yscrollcommand=log_scroll2.set)
log_text.configure(state="disabled")

# Menubar
menubar = Menu(root)
view_menu = Menu(menubar, tearoff=False)
if _USE_BOOTSTRAP:
    themes = ["flatly", "cosmo", "minty", "pulse", "sandstone", "yeti", "journal"]
    sub = Menu(view_menu, tearoff=False)
    for t in themes:
        sub.add_command(label=t.title(), command=lambda n=t: tb.Style().theme_use(n))
    view_menu.add_cascade(label="Bootstrap Theme", menu=sub)
else:
    view_menu.add_command(label="Use Accent Blue", command=lambda: None)
menubar.add_cascade(label="View", menu=view_menu)
root.config(menu=menubar)

# Shortcuts
root.bind("<Control-Return>", lambda e: start_push())
root.bind("<Escape>", lambda e: cancel_run())
root.bind("<Control-l>", lambda e: (log_text.configure(state="normal"), log_text.delete("1.0", END), log_text.configure(state="disabled")))

# Styling

def apply_fallback_style() -> None:
    if _USE_BOOTSTRAP:
        btn_start.configure(bootstyle="PRIMARY")
        overall_progress.configure(bootstyle="success-striped")
        device_progress.configure(bootstyle="info-striped")
        return
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("Accent.Horizontal.TProgressbar", background=ACCENT_HEX)
    overall_progress.configure(style="Accent.Horizontal.TProgressbar")
    device_progress.configure(style="Accent.Horizontal.TProgressbar")
    ioc_text.configure(bg="#FFFFFF", fg="#111827", insertbackground="#111827")
    log_text.configure(bg="#FFFFFF", fg="#111827", insertbackground="#111827")

apply_fallback_style()

if __name__ == "__main__":
    root.mainloop()

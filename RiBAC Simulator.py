#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import logging
import uuid
import os
import threading
from functools import wraps
from flask import Flask, request, jsonify
from collections import defaultdict
from datetime import datetime, time

# Timezone support
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:
    try:
        from backports.zoneinfo import ZoneInfo  # Python <3.9
    except Exception:
        ZoneInfo = None
        logging.warning("Timezone support unavailable. Install 'tzdata' (and 'backports.zoneinfo' on py<3.9).")


log_context = threading.local()

class ContextFilter(logging.Filter):
    """Injects a transaction ID into each log record for correlation."""
    def filter(self, record):
        record.transaction_id = getattr(log_context, 'transaction_id', 'SYSTEM')
        return True

class SIEMFormatter(logging.Formatter):
    """A custom formatter to add SIEM-like colors and structure to logs."""
    # Define ANSI escape codes for colors
    GREY = "\x1b[38;2;170;170;170m"
    GREEN = "\x1b[32;1m"
    YELLOW = "\x1b[33;1m"
    RED = "\x1b[31;1m"
    BOLD_RED = "\x1b[31;1;4m"
    BLUE = "\x1b[34;1m"
    MAGENTA = "\x1b[35;1m"
    CYAN = "\x1b[36;1m"
    WHITE = "\x1b[37;1m"
    RESET = "\x1b[0m"

    LOG_LEVEL_COLORS = {
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: BOLD_RED,
        logging.DEBUG: BLUE,
    }

    def format(self, record):
        # Colorize the log level
        level_color = self.LOG_LEVEL_COLORS.get(record.levelno, self.WHITE)
        level_name = f"{level_color}{record.levelname:<8}{self.RESET}"

        # Format timestamp and transaction ID
        timestamp = self.GREY + datetime.fromtimestamp(record.created).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + self.RESET
        txn_id = self.CYAN + record.transaction_id + self.RESET

        # Colorize the message content based on keywords
        message = record.getMessage()
        if "status=PERMIT" in message or "status=SUCCESS" in message or "status=APPROVED" in message:
            message = message.replace("status=PERMIT", f"status={self.GREEN}PERMIT{self.RESET}")
            message = message.replace("status=SUCCESS", f"status={self.GREEN}SUCCESS{self.RESET}")
            message = message.replace("status=APPROVED", f"status={self.GREEN}APPROVED{self.RESET}")
        elif "status=DENY" in message or "status=FAILURE" in message or "status=BLOCK" in message:
            message = message.replace("status=DENY", f"status={self.RED}DENY{self.RESET}")
            message = message.replace("status=FAILURE", f"status={self.RED}FAILURE{self.RESET}")
            message = message.replace("status=BLOCK", f"status={self.RED}BLOCK{self.RESET}")
        elif "status=NEEDS_APPROVAL" in message or "status=ALERT" in message:
            message = message.replace("status=NEEDS_APPROVAL", f"status={self.YELLOW}NEEDS_APPROVAL{self.RESET}")
            message = message.replace("status=ALERT", f"status={self.YELLOW}ALERT{self.RESET}")
        # Colorize risk levels within messages
        message = message.replace("risk_level=NEGLIGIBLE", f"risk_level={self.GREY}NEGLIGIBLE{self.RESET}")
        message = message.replace("risk_level=LOW", f"risk_level={self.GREEN}LOW{self.RESET}")
        message = message.replace("risk_level=MEDIUM", f"risk_level={self.YELLOW}MEDIUM{self.RESET}")
        message = message.replace("risk_level=HIGH", f"risk_level={self.BOLD_RED}HIGH{self.RESET}")

        # Assemble the final log line
        log_line = f"{timestamp} | {level_name} | TXN:{txn_id} | {message}"
        return log_line

# Setup logger instance
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if logger.hasHandlers(): logger.handlers.clear()
handler = logging.StreamHandler()
handler.setFormatter(SIEMFormatter())
logger.addFilter(ContextFilter())
logger.addHandler(handler)

# --- Transaction ID Decorator ---
def with_transaction_id(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Generate a short, readable transaction ID for the request
        log_context.transaction_id = str(uuid.uuid4())[:8]
        return f(*args, **kwargs)
    return decorated_function

# --- London time + test_at helper ---
try:
    LONDON_TZ = ZoneInfo("Europe/London")
except Exception:
    LONDON_TZ = None
    logger.warning("TIME_CTX | status=UNAVAILABLE reason='Timezone Europe/London not found' suggestion='Install tzdata'")

def _now_london():
    return datetime.now(LONDON_TZ) if LONDON_TZ else datetime.now()

def _parse_test_at(data):
    if not data: return None
    ts = data.get('test_at')
    if not ts: return None
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.astimezone(LONDON_TZ) if LONDON_TZ else dt
    except Exception as e:
        logger.warning(f"TIME_CTX | status=INVALID reason='Bad test_at value' value='{ts}' error='{e}'")
        return None

def is_within_timewindow(window_name, now_dt=None):
    if not window_name or window_name.lower() in {"always","24/7","24x7"}:
        return True
    now = now_dt or _now_london()
    wd = now.weekday(); t = now.time()
    if window_name == "StandardBusinessHours":
        if wd > 4: return False
        return time(8,0) <= t <= time(18,0)
    if window_name == "ExtendedBusinessHours":
        if wd > 5: return False
        return time(7,0) <= t <= time(19,0)
    return False

# --- PIP ---
class PolicyInformationPoint:
    def __init__(self):
        self.users = {
            "manager@example.com": {"password": "ManagerPass123", "role": "Manager"},
            "finance@example.com": {"password": "FinancePass123", "role": "Finance Employee"},
            "auditor@example.com": {"password": "AuditorPass123", "role": "IT Auditor"},
            "itadmin@example.com": {"password": "ITAdminPass123", "role": "IT Admin"}
        }
        # Named locations (HOME & LONDON_OFFICE) using RFC5737 test IPs
        self.registered_locations = {
            "203.0.113.10": "HOME",
            "198.51.100.5": "LONDON_OFFICE"
        }
        # Registered devices
        self.registered_devices = {"DEV-HOME-PC", "DEV-OFFICE-PC"}

        # Resource catalog
        self.resources = {
            "employee_achievements.docx": {"data-classification": "Internal", "resource-type": "internal_file"},
            "client_financials_q3.xlsx": {"data-classification": "Highly Confidential", "resource-type": "sensitive_file"},
            "merger_plan_alpha.docx": {"data-classification": "Critical", "resource-type": "sensitive_file"},
            "vendor_payments.csv": {"resource-type": "financial_data"},
            "customer_database": {"resource-type": "financial_data"},
            "audit_dept_findings_q3.pdf": {"resource-type": "audit_file"},
            "trading_transaction_db": {"resource-type": "transaction_database"},
            "system_event_logs": {"resource-type": "system_log"},
            "database_error_logs": {"resource-type": "system_log"},
            "production_server_config": {"resource-type": "server_config"},
        }

    def get_user_info(self, username): return self.users.get(username)
    def get_resource_attributes(self, resource_id): return self.resources.get(resource_id, {})
    def get_context_attributes(self, ip, device_id):
        return {
            "location_name": self.registered_locations.get(ip),
            "location_is_registered": ip in self.registered_locations,
            "device_is_registered": device_id in self.registered_devices,
        }

# --- Risk Engine ---
def calculate_risk(attrs, breakdown=False, now_dt=None):
    factors = []; score = 0
    action = (attrs.get('action_id') or '').lower()
    rtype = (attrs.get('resource-type') or '').lower()
    clasz = (attrs.get('data-classification') or '').lower()
    within_std = is_within_timewindow("StandardBusinessHours", now_dt=now_dt)

    base_map = {"read":1,"create":2,"write":3,"delete":4,"export":7,"approve":5,"patch_server":6,"create_account":3}
    base = base_map.get(action, 2); score += base; factors.append(("base_"+action, base))

    if "log" in rtype and action == "delete": score += 6; factors.append(("delete_logs", +6))
    if action == "write" and clasz in {"highly confidential","critical"}: score += 5; factors.append(("write_sensitive", +5))
    if action == "export": score += 2; factors.append(("export_bias", +2))
    if action == "patch_server":
        if not attrs.get('change_management_number_provided'): score += 4; factors.append(("no_change_ticket", +4))
        else: score -= 1; factors.append(("has_change_ticket", -1))

    if not attrs.get('location_is_registered', False): score += 2; factors.append(("unreg_location", +2))
    if not attrs.get('device_is_registered', False): score += 3; factors.append(("unreg_device", +3))

    role = (attrs.get('subject_role') or '').lower()
    if role != 'it admin' and not within_std and action in {"create","read","write","delete","export"}:
        score += 2; factors.append(("offhours_non_admin", +2))

    score = max(0, min(10, score))
    if score <= 2: level = "negligible"
    elif score <= 4: level = "low"
    elif score <= 7: level = "medium"
    else: level = "high"
    return (level, score, factors)

def _fmt_factors(factors):
    return ",".join([f"{n}:{'+' if d>=0 else ''}{d}" for n,d in factors if d!=0]) or "none"

# --- PDP (XML loader) ---
class PolicyDecisionPoint:
    def __init__(self, policy_files):
        self.policies = []
        for file in policy_files:
            path = os.path.join(os.path.dirname(__file__), file)
            try:
                tree = ET.parse(path)
                root = tree.getroot()
                for p in root.findall('Policy'):
                    self.policies.append(self._parse_policy(p))
                logger.info(f"POLICY_LOAD | status=SUCCESS file='{file}' rules_loaded={len(root.findall('Policy'))}")
            except Exception as e:
                logger.critical(f"POLICY_LOAD | status=FAILURE file='{file}' error='{e}'")

    def _parse_policy(self, node):
        def txt(tag):
            t = node.findtext(tag)
            return t.strip() if t else None
        role = txt('Role'); op = txt('Operation'); res = txt('Resource') or "Any"
        decision = txt('Decision') or "Allow"; risk_level = txt('RiskLevel')
        risk_score = int(txt('RiskScore') or 0); time_window = txt('TimeWindow')

        cond = node.find('Conditions'); conditions = {}
        if cond is not None:
            ra = cond.findtext('RiskAllowed')
            if ra: conditions['RiskAllowed'] = [x.strip().lower() for x in ra.split(',') if x.strip()]
            conditions['RequiresChangeContext'] = (cond.findtext('RequiresChangeContext') or "false").lower() == "true"
            conditions['AdditionalCondition'] = cond.findtext('AdditionalCondition') or ""
            lc = cond.find('LocationControl')
            if lc is not None:
                allowed = [d.text.strip() for d in lc.findall('./AllowedDevices/Device') if d is not None and d.text]
                other = lc.find('OtherDevices'); other_rules = {}
                if other is not None:
                    other_rules['ApprovalRequired'] = (other.findtext('ApprovalRequired') or 'false').lower() == 'true'
                    other_rules['ApprovalBy'] = other.findtext('ApprovalBy') or 'Manager'
                    other_rules['GrantedPermission'] = other.findtext('GrantedPermission') or 'ReadOnly'
                conditions['LocationControl'] = {'AllowedDevices': allowed, 'OtherDevices': other_rules}
            constraint = cond.findtext('Constraint')
            if constraint: conditions['Constraint'] = constraint
        return {"Role":role,"Operation":op,"Resource":res,"Decision":decision,"RiskLevel":risk_level,"RiskScore":risk_score,"TimeWindow":time_window,"Conditions":conditions}

    @staticmethod
    def _map_resource_to_policy_name(resource_id, attrs, action_id):
        """
        Map a concrete resource to the abstract Resource name used in XML policies.
        """
        rtype = attrs.get('resource-type')
        clasz = (attrs.get('data-classification') or '').lower()

        # Logs
        if resource_id in {"system_event_logs", "database_error_logs"}:
            return "System Logs"

        # NEW: Audit artefacts (by type or by filename)
        if rtype == "audit_file" or resource_id == "audit_dept_findings_q3.pdf":
            return "Audit Files"

        # Server config
        if resource_id == "production_server_config":
            return "Server Configurations"

        # Financial datasets (by id or by declared type)
        if resource_id in {"vendor_payments.csv", "customer_database", "trading_transaction_db"} or rtype == "financial_data":
            return "Financial Data"

        # Sensitive office docs by classification
        if clasz in {"highly confidential", "critical"} and action_id in {"read", "write", "delete"}:
            return "Sensitive Files"

        # Generic internal document
        if resource_id == "employee_achievements.docx" or rtype == "internal_file":
            return "Internal Files"

        # High-privilege admin op remapped to a policy bucket
        if action_id == "patch_server":
            return "High-Privilege: patch_server"

        # Fallback
        return "Any"

    @staticmethod
    def _normalize_operation(action_id):
        if action_id == "patch_server": return "Write"
        if action_id == "create_account": return "Create"
        return action_id.capitalize()

    def find_applicable_policy(self, request_attrs):
        role = request_attrs.get('subject_role')
        action_id = request_attrs.get('action_id')
        resource_id = request_attrs.get('resource_id')

        op = self._normalize_operation(action_id)
        resource_name = self._map_resource_to_policy_name(resource_id, request_attrs, action_id)

        candidates = [p for p in self.policies if p["Role"] == role and p["Operation"] == op and p["Resource"] == resource_name]
        if not candidates:
            candidates = [p for p in self.policies if p["Role"] == role and p["Operation"] == op and p["Resource"] == "Any"]
        if not candidates:
            return None, f"No policy for role={role}, op={op}, resource={resource_name}"

        # Prefer explicit Deny (deny-overrides), then highest RiskScore threshold
        candidates.sort(key=lambda x: (x["Decision"] != "Deny", -x["RiskScore"]))
        return candidates[0], f"Matched {role}/{op}/{resource_name}"

# --- App/State ---
app = Flask(__name__)
pip = PolicyInformationPoint()
pdp = PolicyDecisionPoint(["IT_Admin.xml","Manager.xml","Finance_Employee.xml","IT_Auditor.xml"])

SESSIONS = {}             # token -> username
PENDING_APPROVALS = {}    # req_id -> payload
USER_ACTIVITY_STATS = defaultdict(lambda: defaultdict(int))  # optional feature

def create_pending_approval(username, action_details):
    req_id = f"req_{uuid.uuid4()}"; PENDING_APPROVALS[req_id] = {"username": username, "action_details": action_details}; return req_id

# --- Auth ---
@app.route('/login', methods=['POST'])
@with_transaction_id
def login():
    data = request.get_json()
    test_now = _parse_test_at(data)
    if test_now: logger.info(f"TIME_CTX | event=test_at_override endpoint=login value='{test_now.isoformat()}'")

    username, password = data.get('username'), data.get('password')
    ip = data.get('client_ip') or request.remote_addr
    device = data.get('device_id', 'unknown_device')

    user_info = pip.get_user_info(username)
    if not user_info or user_info['password'] != password:
        logger.error(f"AUTH_EVENT | event=login status=FAILURE user='{username}' src_ip='{ip}' device='{device}' reason='Invalid credentials'")
        return jsonify({"error": "Invalid credentials"}), 401

    context = pip.get_context_attributes(ip, device)
    now_dt = test_now or _now_london()
    within_std = is_within_timewindow("StandardBusinessHours", now_dt)
    within_ext = is_within_timewindow("ExtendedBusinessHours", now_dt)

    if not (context['location_is_registered'] and context['device_is_registered']):
        action_details = {"type": "login_unregistered_device", "context": {"ip": ip, "device": device, "test_at": now_dt.isoformat()}}
        req_id = create_pending_approval(username, action_details)
        logger.warning(f"AUTH_EVENT | event=login status=NEEDS_APPROVAL user='{username}' src_ip='{ip}' device='{device}' reason='Unregistered device/location' request_id='{req_id}'")
        return jsonify({"error": "Approval is required to use this device.", "note": "ONLY READ PERMISSION will be granted...", "request_id": req_id}), 403

    if not within_ext:
        action_details = {"type": "login_offhours", "context": {"ip": ip, "device": device, "test_at": now_dt.isoformat()}}
        req_id = create_pending_approval(username, action_details)
        logger.warning(f"AUTH_EVENT | event=login status=NEEDS_APPROVAL user='{username}' src_ip='{ip}' device='{device}' reason='Outside ExtendedBusinessHours' request_id='{req_id}'")
        return jsonify({"error": "After-hours login requires manager approval.", "request_id": req_id}), 403

    token = str(uuid.uuid4()); SESSIONS[token] = username
    loc_name = context.get('location_name', 'UNKNOWN')
    window = 'STD' if within_std else 'EXT'
    logger.info(f"AUTH_EVENT | event=login status=SUCCESS user='{username}' src_ip='{ip}' location='{loc_name}' device='{device}' window='{window}'")
    return jsonify({"message": "Login successful", "token": token, "window": window})

# --- Access ---
@app.route('/access', methods=['POST'])
@with_transaction_id
def access_resource():
    auth_header = request.headers.get('Authorization'); token = auth_header.split(" ")[1] if auth_header and " " in auth_header else None
    if not token or token not in SESSIONS:
        return jsonify({"error": "Invalid or missing session token"}), 401

    username = SESSIONS[token]; user_info = pip.get_user_info(username)
    data = request.get_json()
    test_now = _parse_test_at(data)
    if test_now: logger.info(f"TIME_CTX | event=test_at_override endpoint=access value='{test_now.isoformat()}'")

    resource_id = data.get('resource_id'); resource_attrs = pip.get_resource_attributes(resource_id)
    customer_id = data.get('customer_id')
    ip = data.get('client_ip') or request.remote_addr
    device = data.get('device_id', 'unknown_device')
    context = pip.get_context_attributes(ip, device)

    request_attrs = {
        "subject_role": user_info['role'], "request_initiator": username,
        "action_id": data.get('action_id'), "resource_id": resource_id,
        "accounts_for_customer": USER_ACTIVITY_STATS[username].get(customer_id, 0),
        "change_management_number_provided": 'change_management_number' in data,
        **resource_attrs, **context
    }

    risk_level, risk_score, factors = calculate_risk(request_attrs, breakdown=True, now_dt=test_now)
    loc = context.get('location_name') or "UNKNOWN"; loc_tag = "reg" if context.get('location_is_registered') else "UNREG"
    dev_tag = "reg" if context.get('device_is_registered') else "UNREG"
    logger.info(
        f"RISK_EVAL | status=CALCULATED user='{username}' role='{user_info['role']}' action='{request_attrs['action_id']}' resource='{resource_id}' "
        f"risk_score={risk_score} risk_level={risk_level.upper()} "
        f"context_location='{loc}({loc_tag})' context_device='{device}({dev_tag})' "
        f"factors='{_fmt_factors(factors)}'"
    )

    policy, match_reason = pdp.find_applicable_policy(request_attrs)
    if not policy:
        logger.warning(f"ACCESS_EVAL | status=DENY user='{username}' reason='No applicable policy' details='{match_reason}' risk_score={risk_score} risk_level={risk_level.upper()}")
        return jsonify({"decision": "Deny", "reason": match_reason, "risk_score": risk_score, "risk_level": risk_level}), 403

    window = policy.get("TimeWindow") or "Always"
    if not is_within_timewindow(window, now_dt=test_now):
        reason = f"Outside permitted time window ({window})"
        logger.warning(f"ACCESS_EVAL | status=BLOCK user='{username}' reason='Time window violation' window='{window}' risk_score={risk_score} risk_level={risk_level.upper()}")
        return jsonify({"decision": "Deny", "reason": reason, "risk_score": risk_score, "risk_level": risk_level}), 403

    allowed_levels = [lvl.lower() for lvl in policy.get("Conditions", {}).get("RiskAllowed", [])]
    if allowed_levels and risk_level not in allowed_levels:
        reason = f"Risk '{risk_level}' ({risk_score}) exceeds allowed levels {allowed_levels}"
        logger.warning(f"ACCESS_EVAL | status=BLOCK user='{username}' reason='Risk threshold exceeded' risk_level={risk_level.upper()} allowed_levels={allowed_levels}")
        return jsonify({"decision": "Deny", "reason": reason, "risk_score": risk_score, "risk_level": risk_level}), 403

    if policy["Decision"].lower() == "deny":
        policy_id = f"{policy['Role']}/{policy['Operation']}/{policy['Resource']}"
        logger.warning(f"ACCESS_EVAL | status=DENY user='{username}' reason='Explicit policy deny' policy='{policy_id}' risk_score={risk_score} risk_level={risk_level.upper()}")
        return jsonify({"decision": "Deny", "reason": "Denied by policy", "risk_score": risk_score, "risk_level": risk_level}), 403

    if policy.get("Conditions", {}).get("AdditionalCondition", "") == "OutsideStandardHoursTriggerAlert" and not is_within_timewindow("StandardBusinessHours", now_dt=test_now):
        logger.warning(f"ACCESS_EVAL | status=ALERT user='{username}' reason='IT Admin action outside StandardBusinessHours'")

    if policy.get("Conditions", {}).get("RequiresChangeContext", False) and not request_attrs.get('change_management_number_provided'):
        logger.warning(f"ACCESS_EVAL | status=DENY user='{username}' reason='Missing Change Management number' risk_score={risk_score} risk_level={risk_level.upper()}")
        return jsonify({"decision": "Deny", "reason": "Change context (CM number) is required.", "risk_score": risk_score, "risk_level": risk_level}), 403

    if (not context['location_is_registered']) or (not context['device_is_registered']):
        granted = "ReadOnly" if (request_attrs['action_id'] or '').lower() != "read" else "Read"
        action_details = {"type": "unregistered_device_action", "original_action": request_attrs['action_id'], "resource_id": resource_id, "granted_permission": granted, "test_at": (test_now.isoformat() if test_now else None)}
        req_id = create_pending_approval(username, action_details)
        logger.warning(f"ACCESS_EVAL | status=NEEDS_APPROVAL user='{username}' reason='Unregistered device/location' request_id='{req_id}' risk_score={risk_score} risk_level={risk_level.upper()}")
        return jsonify({"decision": "NeedsApproval", "message": "Unregistered device/location requires approval. Read-only access granted.", "request_id": req_id, "risk_score": risk_score, "risk_level": risk_level}), 202

    if request_attrs['action_id'] == 'create_account' and USER_ACTIVITY_STATS[username].get(customer_id, 0) >= 5:
        action_details = {"type": "create_account", "customer_id": customer_id, "test_at": (test_now.isoformat() if test_now else None)}
        req_id = create_pending_approval(username, action_details)
        logger.warning(f"ACCESS_EVAL | status=NEEDS_APPROVAL user='{username}' reason='Account creation limit exceeded' request_id='{req_id}' risk_score={risk_score} risk_level={risk_level.upper()}")
        return jsonify({"decision": "NeedsApproval", "message": "Exceeded 5 accounts for customer. Manager approval required.", "request_id": req_id, "risk_score": risk_score, "risk_level": risk_level}), 202

    if request_attrs['action_id'] == 'create_account':
        USER_ACTIVITY_STATS[username][customer_id] += 1

    policy_id = f"{policy['Role']}/{policy['Operation']}/{policy['Resource']}"
    logger.info(f"ACCESS_EVAL | status=PERMIT user='{username}' action='{request_attrs['action_id']}' resource='{resource_id}' policy='{policy_id}' risk_score={risk_score} risk_level={risk_level.upper()}")
    return jsonify({"decision": "Permit", "reason": "Permitted by policy and risk thresholds", "risk_score": risk_score, "risk_level": risk_level})

# --- Approvals ---
@app.route('/approve', methods=['POST'])
@with_transaction_id
def approve_request():
    auth_header = request.headers.get('Authorization'); token = auth_header.split(" ")[1] if auth_header and " " in auth_header else None
    if not token or token not in SESSIONS: return jsonify({"error": "Invalid or missing session token"}), 401

    approver = SESSIONS[token]; role = (pip.get_user_info(approver) or {}).get('role')
    if role != 'Manager':
        logger.error(f"APPROVAL_EVENT | status=FAILURE approver='{approver}' reason='Not a manager'")
        return jsonify({"error": "Only managers can approve requests"}), 403

    data = request.get_json(); req_id = data.get('request_id'); pending_req = PENDING_APPROVALS.get(req_id)
    if not pending_req:
        logger.error(f"APPROVAL_EVENT | status=FAILURE approver='{approver}' request_id='{req_id}' reason='Invalid or expired request ID'")
        return jsonify({"error": "Invalid or expired request ID"}), 404

    original_user = pending_req['username']; action_details = pending_req['action_details']
    if original_user == approver:
        logger.error(f"APPROVAL_EVENT | status=FAILURE approver='{approver}' request_id='{req_id}' reason='Self-approval not permitted'")
        return jsonify({"error": "Self-approval is not permitted"}), 403

    del PENDING_APPROVALS[req_id]  # Optimistically remove

    if action_details['type'] == 'login_unregistered_device':
        new_token = str(uuid.uuid4()); SESSIONS[new_token] = original_user
        logger.info(f"APPROVAL_EVENT | status=APPROVED type='login_unregistered' approver='{approver}' user='{original_user}' outcome='Read-only token issued'")
        return jsonify({"message": "Login approved. Read-only access granted.", "read_only": True, "one_time_token": new_token})

    if action_details['type'] == 'login_offhours':
        new_token = str(uuid.uuid4()); SESSIONS[new_token] = original_user
        logger.info(f"APPROVAL_EVENT | status=APPROVED type='login_offhours' approver='{approver}' user='{original_user}' outcome='Full token issued'")
        return jsonify({"message": "After-hours login approved.", "one_time_token": new_token})

    if action_details['type'] == 'create_account':
        USER_ACTIVITY_STATS[original_user][action_details['customer_id']] += 1
        logger.info(f"APPROVAL_EVENT | status=APPROVED type='create_account' approver='{approver}' user='{original_user}'")
        return jsonify({"message": "Account creation approved."})

    if action_details['type'] == 'unregistered_device_action':
        one_time_token = str(uuid.uuid4()); SESSIONS[one_time_token] = original_user
        logger.info(f"APPROVAL_EVENT | status=APPROVED type='unregistered_action' approver='{approver}' user='{original_user}' outcome='Read-only token issued'")
        return jsonify({"message": "Action approved. Read-only access granted.", "read_only": True, "one_time_token": one_time_token})

    PENDING_APPROVALS[req_id] = pending_req  # Put it back if unknown
    logger.error(f"APPROVAL_EVENT | status=FAILURE approver='{approver}' request_id='{req_id}' reason='Unknown request type' type='{action_details.get('type')}'")
    return jsonify({"error": "Unknown approval request type"}), 400

# --- Bootstrap ---
if __name__ == '__main__':
    banner_color = SIEMFormatter.MAGENTA
    reset = SIEMFormatter.RESET
    logger.info(f"{banner_color}============================================================={reset}")
    logger.info(f"{banner_color}    Policy-Driven Access Control Server (Role + Risk + Time) {reset}")
    logger.info(f"{banner_color}    SIEM Logging Mode: {SIEMFormatter.GREEN}ACTIVE{reset}{banner_color}                             {reset}")
    logger.info(f"{banner_color}============================================================={reset}")
    app.run(host='127.0.0.1', port=5000, debug=False)

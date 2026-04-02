import uuid
from datetime import datetime


class SessionState:
    PHASES = [
        "RECON",
        "ENUMERATION",
        "INITIAL_ACCESS",
        "EXPLOITATION",
        "POST_ACCESS",
        "PRIVILEGE_ESCALATION",
        "COMPLETE",
    ]

    def __init__(self, target_ip):
        self.session_id = str(uuid.uuid4())
        self.action_attempts = {}

        self.target = {
            "ip": target_ip,
            "hostname": None,
            "os": "unknown",
        }
        self.phase = "RECON"
        self.status = "RUNNING"

        self.network = {
            "open_ports": [],
            "services": {},
        }
        self.access = {
            "credentials": [],
            "shells": {
                "low_priv": False,
                "high_priv": False,
                "user": None,
            },
        }
        self.privesc = {
            "kernel": None,
            "suid_bins": [],
            "cron_jobs": [],
            "writable_paths": [],
        }
        self.constraints = {
            "stealth": True,
            "no_bruteforce": True,
            "web_only": False,
        }

        self.created_at = datetime.utcnow().isoformat()
        self.last_updated = self.created_at
        self.failed_actions = set()
        self.last_action = None
        self.actions_taken = []
        self.attack_surface = {}
        self.credentials = []
        self.compromised = False
        self.escalated = False
        self.internal_networks = []
        self.pivot_targets = []
        self.session_data = {}

        self.access["ftp"] = {
            "listing": [],
            "cwd": "/",
            "writable_dirs": [],
            "uploaded_files": [],
        }
        self.access["web"] = {
            "accessible_files": [],
            "web_root": None,
            "php_execution": False,
            "php_probe_url": None,
        }
        self.user_consent = {
            "reverse_shell": False,
            "timestamp": None,
        }
        self.post_exploit = {
            "enumeration": {},
            "privesc_candidates": [],
            "ranked_privesc": [],
            "best_privesc": None,
            "user": None,
            "privilege": "unknown",
        }

        # Persistence control modes:
        # "AUTO" -> automatic persistence
        # "MANUAL" -> ask before installing
        # "OFF" -> disabled
        self.persistence_mode = "MANUAL"
        self.persistence_installed = False

    @property
    def target_ip(self):
        return self.target.get("ip")

    def update_phase(self, new_phase):
        self.phase = new_phase
        self.last_updated = datetime.utcnow().isoformat()

    def summary(self):
        return {
            "session_id": self.session_id,
            "target": self.target,
            "phase": self.phase,
            "status": self.status,
            "open_ports": self.network["open_ports"],
            "services": self.network["services"],
            "actions_taken": self.actions_taken,
            "last_updated": self.last_updated,
        }

    def should_move_to_initial_access(self):
        return len(self.network["open_ports"]) > 0

    def has_initial_access(self):
        return len(self.access["credentials"]) > 0

    def mark_action_failed(self, action_name):
        self.failed_actions.add(action_name)

    def is_action_failed(self, action_name):
        return action_name in self.failed_actions

    def store_ftp_listing(self, files):
        self.access["ftp"]["listing"] = files

    def has_ftp_listing(self):
        return len(self.access["ftp"]["listing"]) > 0

    def add_writable_dir(self, path):
        if path not in self.access["ftp"]["writable_dirs"]:
            self.access["ftp"]["writable_dirs"].append(path)

    def add_uploaded_file(self, path):
        if path not in self.access["ftp"]["uploaded_files"]:
            self.access["ftp"]["uploaded_files"].append(path)

    def has_uploaded_files(self):
        return len(self.access["ftp"]["uploaded_files"]) > 0

    def add_web_accessible_file(self, url):
        if url not in self.access["web"]["accessible_files"]:
            self.access["web"]["accessible_files"].append(url)

    def has_web_access(self):
        return len(self.access["web"]["accessible_files"]) > 0

    def mark_php_execution(self, url):
        self.access["web"]["php_execution"] = True
        self.access["web"]["php_probe_url"] = url

    def has_php_execution(self):
        return self.access["web"]["php_execution"] is True

    def grant_reverse_shell_consent(self):
        self.user_consent["reverse_shell"] = True
        self.user_consent["timestamp"] = datetime.utcnow().isoformat()

    def has_reverse_shell_consent(self):
        return self.user_consent["reverse_shell"] is True

    def move_to_post_exploit(self):
        self.phase = "POST_EXPLOIT"
        self.last_updated = datetime.utcnow().isoformat()

    def record_post_enum(self, key, value):
        self.post_exploit["enumeration"][key] = value

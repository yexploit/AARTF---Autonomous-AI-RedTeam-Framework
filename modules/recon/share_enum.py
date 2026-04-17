import shutil
import subprocess


class ShareEnumerationModule:
    NAME = "share_enumeration"

    def discover(self, state):
        if state.phase != "ENUMERATION":
            return []
        if not any(port in state.services_detail for port in ("139", "445", "2049", "111")):
            return []
        return [{"name": self.NAME, "type": "recon"}]

    def execute(self, state):
        target = state.target_ip
        findings_added = 0
        summaries = []

        if any(port in state.services_detail for port in ("139", "445")):
            smb_summary = self._enumerate_smb(target, state)
            if smb_summary:
                summaries.append(smb_summary)
                findings_added += 1

        if any(port in state.services_detail for port in ("111", "2049")):
            nfs_summary = self._enumerate_nfs(target, state)
            if nfs_summary:
                summaries.append(nfs_summary)
                findings_added += 1

        if not summaries:
            return {
                "success": True,
                "summary": "No share enumeration completed; required client tools were unavailable or no data was returned",
            }

        return {
            "success": True,
            "summary": "; ".join(summaries),
        }

    def _enumerate_smb(self, target, state):
        if not shutil.which("smbclient"):
            state.add_learning_note(
                "SMB client unavailable",
                "Install `smbclient` to enable guest-style share discovery against SMB targets.",
            )
            return None

        try:
            proc = subprocess.run(
                ["smbclient", "-L", f"//{target}", "-N"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=12,
                check=False,
            )
            output = proc.stdout.decode("utf-8", errors="ignore")
            if not output.strip():
                return None

            shares = []
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] not in {"Sharename", "Server", "Workgroup"} and not line.startswith("\t"):
                    share = parts[0]
                    if share not in {"SMB1", "Reconnecting"} and share.isprintable():
                        shares.append(share)

            state.attack_surface.setdefault("share_enumeration", {})["smb"] = {
                "raw": output,
                "shares": shares,
            }
            state.add_learning_note(
                "SMB share discovery",
                f"Guest-style SMB enumeration returned {len(shares)} candidate shares.",
            )
            if shares:
                state.add_finding(
                    {
                        "title": "SMB shares enumerated without supplied credentials",
                        "type": "smb_share_listing",
                        "severity": "HIGH",
                        "confidence": 84,
                        "description": "SMB enumeration returned share names without explicitly providing credentials, which strongly improves the file-sharing attack path.",
                        "summary": "Guest or low-friction SMB enumeration exposed share metadata.",
                        "evidence": [f"Shares: {', '.join(shares[:6])}"],
                        "affected_service": "smb",
                        "affected_port": "445",
                        "kill_chain_stage": "Enumeration",
                        "attack_opportunities": [
                            "Prioritize shares for readable content, configs, backups, or credential artifacts.",
                            "Use share names to infer host role and intended learner path.",
                        ],
                        "verification_steps": [
                            "Review which shares appear public, administrative, or application-related.",
                            "Correlate share names with Windows/RPC findings and host role clues.",
                        ],
                        "remediation": [
                            "Disable guest access and reduce anonymous share metadata exposure.",
                            "Restrict share access to authorized users only.",
                        ],
                        "source": self.NAME,
                    }
                )
            return f"SMB shares discovered: {len(shares)}"
        except Exception as exc:
            state.add_learning_note("SMB share discovery error", str(exc))
            return None

    def _enumerate_nfs(self, target, state):
        if not shutil.which("showmount"):
            state.add_learning_note(
                "NFS tooling unavailable",
                "Install `showmount` to enumerate exports from NFS-exposed hosts.",
            )
            return None

        try:
            proc = subprocess.run(
                ["showmount", "-e", target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=12,
                check=False,
            )
            output = proc.stdout.decode("utf-8", errors="ignore")
            if not output.strip():
                return None

            exports = []
            for line in output.splitlines():
                line = line.strip()
                if not line or line.lower().startswith("export list"):
                    continue
                exports.append(line)

            state.attack_surface.setdefault("share_enumeration", {})["nfs"] = {
                "raw": output,
                "exports": exports,
            }
            state.add_learning_note(
                "NFS export discovery",
                f"NFS export enumeration returned {len(exports)} exported paths.",
            )
            if exports:
                state.add_finding(
                    {
                        "title": "NFS exports enumerated from the target",
                        "type": "nfs_export_listing",
                        "severity": "HIGH",
                        "confidence": 82,
                        "description": "NFS export metadata was available from the target, which strengthens file-based attack-path analysis.",
                        "summary": "Exposed NFS exports can reveal application content, credentials, or writable paths.",
                        "evidence": exports[:5],
                        "affected_service": "nfs",
                        "affected_port": "2049",
                        "kill_chain_stage": "Enumeration",
                        "attack_opportunities": [
                            "Prioritize exports that may hold web roots, home directories, or backups.",
                            "Use export paths to refine later credential and content discovery paths.",
                        ],
                        "verification_steps": [
                            "Review export names and permitted client scopes.",
                            "Identify whether the exports align with application or user-content directories.",
                        ],
                        "remediation": [
                            "Restrict exported paths and trusted client scopes.",
                            "Avoid exposing sensitive data over NFS to broad networks.",
                        ],
                        "source": self.NAME,
                    }
                )
            return f"NFS exports discovered: {len(exports)}"
        except Exception as exc:
            state.add_learning_note("NFS export discovery error", str(exc))
            return None

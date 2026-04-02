#!/usr/bin/env python3

import argparse
from core.engine import AttackEngine
from core.multi_target_controller import MultiTargetController
from core.state import SessionState


def main():
    parser = argparse.ArgumentParser(
        description="AARTF - Autonomous AI Red Team Framework"
    )
    parser.add_argument(
        "-t", "--target",
        required=False,
        help="Target IP address (HTB / THM / Lab)"
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Start interactive (chat-style) mode"
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Start GUI dashboard"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Max worker threads for subnet mode"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate reports after run"
    )

    args = parser.parse_args()

    if args.gui:
        import tkinter as tk
        from gui_dashboard import AARTF_GUI

        root = tk.Tk()
        AARTF_GUI(root)
        root.mainloop()
        return

    if not args.target:
        parser.error("the following arguments are required: -t/--target (unless using --gui)")

    print("[+] Initializing session...")

    if "/" in args.target:
        controller = MultiTargetController(args.target, max_threads=max(1, args.threads))
        print(f"[+] Subnet mode active: {args.target}")
        controller.run()
        return

    state = SessionState(target_ip=args.target)
    engine = AttackEngine(state)

    print(f"[+] Target set: {args.target}")
    print("[+] Engine initialized")
    engine.run()

    if args.report:
        engine.generate_reports()


if __name__ == "__main__":
    main()

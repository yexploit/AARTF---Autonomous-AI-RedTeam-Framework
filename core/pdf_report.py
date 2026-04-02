import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import black, grey, lightgrey


class PDFReportGenerator:

    def __init__(self, state):

        self.state = state

        if isinstance(state.target, dict):
            self.target = state.target.get("ip", "unknown")
        else:
            self.target = str(state.target)

        self.report_dir = "reports"

        os.makedirs(self.report_dir, exist_ok=True)

        self.filename = f"{self.report_dir}/attack_report_{self.target}.pdf"

        self.styles = getSampleStyleSheet()

        self.title_style = ParagraphStyle(
            name="TitleStyle",
            fontSize=24,
            leading=30,
            spaceAfter=20,
        )

        self.heading_style = ParagraphStyle(
            name="HeadingStyle",
            fontSize=16,
            leading=22,
            spaceAfter=10,
        )

        self.normal_style = ParagraphStyle(
            name="NormalStyle",
            fontSize=11,
            leading=16,
            spaceAfter=6,
        )

    def generate(self):

        doc = SimpleDocTemplate(
            self.filename,
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        elements = []

        # Title
        elements.append(
            Paragraph(
                "Autonomous Red Team Attack Report",
                self.title_style,
            )
        )

        # Basic info
        elements.append(
            Paragraph(f"<b>Target:</b> {self.target}", self.normal_style)
        )

        elements.append(
            Paragraph(
                f"<b>Generated:</b> {datetime.now()}",
                self.normal_style,
            )
        )

        elements.append(Spacer(1, 12))

        # Executive Summary
        elements.append(
            Paragraph("Executive Summary", self.heading_style)
        )

        summary = getattr(self.state, "ai_analysis", None)

        if summary:
            elements.append(
                Paragraph(str(summary), self.normal_style)
            )
        else:
            elements.append(
                Paragraph(
                    "Automated reconnaissance and analysis completed.",
                    self.normal_style,
                )
            )

        elements.append(Spacer(1, 12))

        # Open Ports Table
        elements.append(
            Paragraph("Open Ports", self.heading_style)
        )

        open_ports = self.state.network.get("open_ports", {})

        if open_ports:

            table_data = [["Port", "Service"]]

            for port, service in open_ports.items():
                table_data.append([str(port), str(service)])

            table = Table(table_data)

            table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), black),
                    ("GRID", (0, 0), (-1, -1), 0.5, black),
                    ("BACKGROUND", (0, 1), (-1, -1), lightgrey),
                ])
            )

            elements.append(table)

        else:

            elements.append(
                Paragraph("No open ports detected.", self.normal_style)
            )

        elements.append(Spacer(1, 12))

        # Vulnerabilities
        elements.append(
            Paragraph("Detected Vulnerabilities", self.heading_style)
        )

        vulns = self.state.network.get("vulnerabilities", [])

        if vulns:

            for vuln in vulns:

                text = (
                    f"<b>Type:</b> {vuln.get('type')}<br/>"
                    f"<b>Severity:</b> {vuln.get('severity')}<br/>"
                    f"<b>Description:</b> {vuln.get('description')}"
                )

                elements.append(
                    Paragraph(text, self.normal_style)
                )

                elements.append(Spacer(1, 6))

        else:

            elements.append(
                Paragraph(
                    "No vulnerabilities detected.",
                    self.normal_style,
                )
            )

        elements.append(Spacer(1, 12))

        # Attack Plan
        elements.append(
            Paragraph("AI Attack Plan", self.heading_style)
        )

        attack_plan = getattr(self.state, "attack_plan", {})

        if attack_plan:

            elements.append(
                Paragraph(
                    f"<b>Best Path:</b> {attack_plan.get('best_path')}",
                    self.normal_style,
                )
            )

            elements.append(
                Paragraph(
                    f"<b>Confidence:</b> {attack_plan.get('confidence')}",
                    self.normal_style,
                )
            )

            elements.append(
                Paragraph(
                    f"<b>Reason:</b> {attack_plan.get('reason')}",
                    self.normal_style,
                )
            )

        else:

            elements.append(
                Paragraph(
                    "No attack plan generated.",
                    self.normal_style,
                )
            )

        elements.append(Spacer(1, 12))

        # Recommendations
        elements.append(
            Paragraph("Recommendations", self.heading_style)
        )

        recommendations = [
            "Restrict exposed services",
            "Secure administrative interfaces",
            "Apply security patches",
            "Monitor suspicious activity",
            "Perform regular security assessments",
        ]

        for rec in recommendations:

            elements.append(
                Paragraph(f"• {rec}", self.normal_style)
            )

        # Build PDF
        doc.build(elements)

        print(f"[+] Professional PDF report generated: {self.filename}")

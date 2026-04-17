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
        safe_target = self.target.replace(".", "_").replace("/", "_")

        os.makedirs(self.report_dir, exist_ok=True)

        self.filename = f"{self.report_dir}/attack_report_{safe_target}.pdf"

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
        self.state.finalize_assessment()
        doc = SimpleDocTemplate(
            self.filename,
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        elements = []

        elements.append(
            Paragraph(
                "AARTF Advisory Assessment Report",
                self.title_style,
            )
        )

        elements.append(
            Paragraph(f"<b>Target:</b> {self.target}", self.normal_style)
        )

        elements.append(
            Paragraph(
                f"<b>Generated:</b> {datetime.now()}",
                self.normal_style,
            )
        )
        elements.append(
            Paragraph(
                f"<b>AI Mode:</b> {self.state.ai_status.get('mode')} ({self.state.ai_status.get('detail')})",
                self.normal_style,
            )
        )

        elements.append(Spacer(1, 12))

        self._add_section(
            elements,
            "Executive Summary",
            [
                self.state.executive_summary or "Automated reconnaissance and advisory analysis completed.",
                f"Overall Risk: {self.state.assessment['risk_rating']} ({self.state.assessment['risk_score']}/100)",
                f"Average Confidence: {self.state.assessment['confidence']}",
            ],
        )

        service_rows = [["Port", "Service", "Details"]]
        for port, service in sorted(self.state.services_detail.items(), key=lambda item: int(item[0])):
            detail = ", ".join(
                part for part in [service.get("product"), service.get("version"), service.get("extrainfo")] if part
            ) or (service.get("banner") or "-")
            service_rows.append([str(port), str(service.get("service", "unknown")), detail[:80]])
        self._add_table_or_message(elements, "Service Inventory", service_rows, "No services detected.")

        finding_lines = []
        for finding in self.state.findings[:12]:
            finding_lines.append(
                f"<b>{finding['title']}</b> [{finding['severity']}]<br/>"
                f"Confidence: {finding['confidence']}<br/>"
                f"{finding.get('summary') or finding.get('description', '')}<br/>"
                f"Evidence: {' | '.join(finding.get('evidence', [])[:2]) or 'Not captured'}"
            )
        self._add_section(elements, "Findings", finding_lines or ["No findings detected."])

        path_lines = []
        for attack_path in self.state.attack_paths[:6]:
            steps = "<br/>".join(f"- {step}" for step in attack_path.get("steps", [])[:4])
            path_lines.append(
                f"<b>{attack_path['title']}</b> [{attack_path['severity']}] score={attack_path['score']} confidence={attack_path['confidence']}<br/>"
                f"{attack_path.get('summary', '')}<br/>{steps}"
            )
        self._add_section(elements, "Prioritized Attack Paths", path_lines or ["No attack paths generated."])

        walkthrough_lines = [f"{idx}. {step}" for idx, step in enumerate(self.state.walkthrough or [], start=1)]
        self._add_section(elements, "Learner Walkthrough", walkthrough_lines or ["No walkthrough available."])

        recommendation_lines = [
            f"[{rec['priority']}] <b>{rec['title']}</b><br/>{rec['details']}"
            for rec in self.state.recommendations
        ]
        self._add_section(elements, "Recommendations", recommendation_lines or ["No recommendations recorded."])

        doc.build(elements)

        print(f"[+] Professional PDF report generated: {self.filename}")

    def _add_section(self, elements, title, paragraphs):
        elements.append(Paragraph(title, self.heading_style))
        for paragraph in paragraphs:
            elements.append(Paragraph(str(paragraph), self.normal_style))
            elements.append(Spacer(1, 6))
        elements.append(Spacer(1, 8))

    def _add_table_or_message(self, elements, title, rows, empty_message):
        elements.append(Paragraph(title, self.heading_style))
        if len(rows) <= 1:
            elements.append(Paragraph(empty_message, self.normal_style))
            elements.append(Spacer(1, 8))
            return
        table = Table(rows, colWidths=[0.8 * inch, 1.2 * inch, 4.4 * inch])
        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), black),
                ("GRID", (0, 0), (-1, -1), 0.5, black),
                ("BACKGROUND", (0, 1), (-1, -1), lightgrey),
            ])
        )
        elements.append(table)
        elements.append(Spacer(1, 8))

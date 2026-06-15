from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
import os

OUTPUT = r"d:\network 1\aegisai-x\AegisAI-X_Project_Report.pdf"

# Colours
NAVY    = colors.HexColor("#0A1628")
BLUE    = colors.HexColor("#1E3A5F")
ACCENT  = colors.HexColor("#00D4FF")
GREEN   = colors.HexColor("#00C896")
WHITE   = colors.white
BLACK   = colors.HexColor("#0D1117")
LGRAY   = colors.HexColor("#F4F6F9")
MGRAY   = colors.HexColor("#8A9BB0")

doc = SimpleDocTemplate(
    OUTPUT,
    pagesize=A4,
    leftMargin=2*cm, rightMargin=2*cm,
    topMargin=2.5*cm, bottomMargin=2.5*cm,
    title="AegisAI-X Project Report"
)

styles = getSampleStyleSheet()

H1 = ParagraphStyle("H1", fontSize=26, textColor=WHITE, fontName="Helvetica-Bold", spaceAfter=6, alignment=TA_CENTER)
H2 = ParagraphStyle("H2", fontSize=14, textColor=ACCENT, fontName="Helvetica-Bold", spaceBefore=18, spaceAfter=6)
H3 = ParagraphStyle("H3", fontSize=11, textColor=GREEN, fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4)
BODY = ParagraphStyle("BODY", fontSize=9.5, textColor=BLACK, fontName="Helvetica", leading=15, spaceAfter=6)
BULLET = ParagraphStyle("BULLET", fontSize=9.5, textColor=BLACK, fontName="Helvetica", leading=14, leftIndent=14, spaceAfter=3, bulletIndent=4, bulletText="•")
SMALL = ParagraphStyle("SMALL", fontSize=8.5, textColor=MGRAY, fontName="Helvetica", leading=12)
SUBTITLE = ParagraphStyle("SUBTITLE", fontSize=12, textColor=ACCENT, fontName="Helvetica", alignment=TA_CENTER, spaceAfter=4)
CAPTION = ParagraphStyle("CAPTION", fontSize=8, textColor=MGRAY, fontName="Helvetica-Oblique", alignment=TA_CENTER)

def hr(color=ACCENT, thickness=1.5):
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=8, spaceBefore=4)

def table(data, col_widths, header_row=True):
    tbl_style = [
        ("BACKGROUND", (0, 0), (-1, 0 if header_row else -1), BLUE if header_row else LGRAY),
        ("TEXTCOLOR",  (0, 0), (-1, 0), WHITE if header_row else BLACK),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LGRAY]),
        ("ALIGN",      (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING",    (0, 0), (-1, -1), 6),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.grey),
    ]
    formatted_data = []
    for r_i, row in enumerate(data):
        new_row = []
        for c_i, cell in enumerate(row):
            txt_color = WHITE if (r_i == 0 and header_row) else BLACK
            fnt = "Helvetica-Bold" if r_i == 0 else "Helvetica"
            new_row.append(Paragraph(str(cell), ParagraphStyle("tc", fontSize=8.5, textColor=txt_color, fontName=fnt, leading=12)))
        formatted_data.append(new_row)
    t = Table(formatted_data, colWidths=col_widths)
    t.setStyle(TableStyle(tbl_style))
    return t

story = []
banner = Table([[Paragraph("🛡️ AegisAI-X", H1)]], colWidths=["100%"])
banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("PADDING", (0, 0), (-1, -1), 20)]))
story.append(banner)
story.append(Spacer(1, 0.3*cm))
story.append(Paragraph("Security Operations Centre Platform", SUBTITLE))
story.append(Paragraph("Project Report — Phase 1", SMALL))
story.append(hr())

story.append(Paragraph("What Is AegisAI-X?", H2))
story.append(hr(MGRAY, 0.5))
story.append(Paragraph("<b>AegisAI-X</b> is a production-grade <b>Security Operations Centre (SOC) platform</b> designed to protect web infrastructure. It acts as a smart gateway that sits in front of websites, monitors traffic patterns, and automatically neutralizes attacks. It provides a central command center for security analysts to investigate and manage incidents in real time.", BODY))

story.append(Paragraph("Architecture & Tech Stack", H2))
story.append(hr(MGRAY, 0.5))
arch_data = [
    ["Component", "Technology Used", "Role"],
    ["Gateway", "Nginx + ModSecurity WAF + OWASP CRS", "Edge protection & attack blocking"],
    ["Pipeline", "Filebeat + 5 Python Workers", "Secure log shipping & enrichment"],
    ["Brain", "Correlation Engine + ClickHouse", "Detecting complex attack patterns"],
    ["Storage", "Clickhouse + Postgres + Redis", "Logs, Incidents, and real-time Cache"],
    ["API", "FastAPI (Python)", "Backend logic, RBAC, and Authentication"],
    ["UI", "React SPA", "SOC Analyst Dashboard"],
    ["Ops", "Prometheus + Grafana + Docker + Ansible", "Monitoring, Alerting, and Deployment"]
]
story.append(table(arch_data, [4*cm, 6*cm, 6.5*cm]))

story.append(Paragraph("Attacks Prevented", H2))
story.append(hr(MGRAY, 0.5))
attacks = [["Attack Type", "Prevention Mechanism"], ["SQL Injection / XSS", "WAF Signature blocking at the gateway"], ["Brute Force", "Auth failure rate rule → Auto IP block"], ["DDoS / Flooding", "Traffic spike detection + mass block alerts"], ["Botnets", "Cross-site pattern correlation across the entire network"], ["Log Forgery", "HMAC-SHA256 signature validation on every log batch"]]
story.append(table(attacks, [6*cm, 10.5*cm]))

story.append(Paragraph("Current Status (Phase 1)", H2))
story.append(hr(MGRAY, 0.5))
story.append(Paragraph("Phase 1 is <b>fully complete</b>. The system is deployable via Ansible and provides real-time observability through automated alerts and a responsive SOC dashboard. It is currently protecting infrastructure against common web vulnerabilities and sophisticated coordinated attacks.", BODY))

def on_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY); canvas.rect(0, A4[1]-1.2*cm, A4[0], 1.2*cm, fill=1, stroke=0)
    canvas.setFillColor(WHITE); canvas.setFont("Helvetica-Bold", 10); canvas.drawString(1*cm, A4[1]-0.8*cm, "🛡️ AegisAI-X")
    canvas.setFillColor(NAVY); canvas.rect(0, 0, A4[0], 1*cm, fill=1, stroke=0)
    canvas.setFillColor(WHITE); canvas.setFont("Helvetica", 8); canvas.drawRightString(A4[0]-1*cm, 0.4*cm, f"Page {doc.page}")
    canvas.restoreState()

doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
print("PDF Generated.")

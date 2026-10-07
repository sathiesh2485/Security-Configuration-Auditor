from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.lib.units import inch
from pathlib import Path


def generate_pdf_report(results):

    output_path = Path(__file__).parent / "security_audit_report.pdf"

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=15,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=6
    )

    story = []

    # --------------------------------------------------
    # Report Title
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Security Configuration Audit Report",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Security Configuration Auditor using Context-Aware Threat Intelligence",
            body_style
        )
    )

    story.append(Spacer(1, 15))

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    story.append(
        Paragraph("Audit Summary", heading_style)
    )

    total_findings = len(results)

    high_count = sum(
        1 for result in results
        if result["severity"] == "High"
    )

    medium_count = sum(
        1 for result in results
        if result["severity"] == "Medium"
    )

    low_count = sum(
        1 for result in results
        if result["severity"] == "Low"
    )

    summary_data = [
        ["Total Findings", str(total_findings)],
        ["High Severity", str(high_count)],
        ["Medium Severity", str(medium_count)],
        ["Low Severity", str(low_count)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[2.5 * inch, 2 * inch]
    )

    summary_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8)
        ])
    )

    story.append(summary_table)
    story.append(Spacer(1, 20))

    # --------------------------------------------------
    # Finding Details
    # --------------------------------------------------

    for index, result in enumerate(results, start=1):

        story.append(
            Paragraph(
                f"Finding {index}: {result['issue']}",
                heading_style
            )
        )

        finding_data = [
            ["Configuration", result["configuration"]],
            ["Category", result["category"]],
            ["Evidence", result["evidence"]],
            ["Severity", result["severity"]],
            ["Threat", result["threat"]],
            ["Impact", result["impact"]],
            ["Context", result["context"]],
            ["Severity Reason", result["severity_reason"]],
            ["Recommendation", result["recommendation"]],
            ["Action", result["action"]]
        ]

        finding_table = Table(
            finding_data,
            colWidths=[1.5 * inch, 4.8 * inch]
        )

        finding_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 11),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6)
            ])
        )

        story.append(finding_table)
        story.append(Spacer(1, 12))

        # --------------------------------------------------
        # AI Analysis
        # --------------------------------------------------

        story.append(
            Paragraph(
                "AI Security Analysis",
                heading_style
            )
        )

        ai_text = result["ai_explanation"]

        # Convert line breaks to HTML breaks for ReportLab
        ai_text = ai_text.replace("\n", "<br/>")

        story.append(
            Paragraph(
                ai_text,
                body_style
            )
        )

        if index != len(results):
            story.append(PageBreak())

    # --------------------------------------------------
    # Build PDF
    # --------------------------------------------------

    document.build(story)

    return output_path


if __name__ == "__main__":

    from audit_processor import process_findings

    results = process_findings()

    report_path = generate_pdf_report(results)

    print("\nPDF report generated successfully.")
    print("Report location:")
    print(report_path)

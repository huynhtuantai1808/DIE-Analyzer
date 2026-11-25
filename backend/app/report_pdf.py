import html
import io
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors, pagesizes
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Register Unicode fonts for full Vietnamese support
FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")
if (FONT_DIR / "DejaVuSans.ttf").exists():
    try:
        pdfmetrics.registerFont(TTFont("DejaVu", str(FONT_DIR / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont("DejaVu-Bold", str(FONT_DIR / "DejaVuSans-Bold.ttf")))
        pdfmetrics.registerFont(TTFont("DejaVuMono", str(FONT_DIR / "DejaVuSansMono.ttf")))
        pdfmetrics.registerFont(TTFont("DejaVuMono-Bold", str(FONT_DIR / "DejaVuSansMono-Bold.ttf")))
        DEFAULT_FONT = "DejaVu"
        BOLD_FONT = "DejaVu-Bold"
        MONO_FONT = "DejaVuMono"
        MONO_BOLD_FONT = "DejaVuMono-Bold"
    except Exception:
        DEFAULT_FONT = "Helvetica"
        BOLD_FONT = "Helvetica-Bold"
        MONO_FONT = "Courier"
        MONO_BOLD_FONT = "Courier-Bold"
else:
    DEFAULT_FONT = "Helvetica"
    BOLD_FONT = "Helvetica-Bold"
    MONO_FONT = "Courier"
    MONO_BOLD_FONT = "Courier-Bold"


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and draw total page numbers and running footers."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont(DEFAULT_FONT, 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Top running header on pages > 1
        if self._pageNumber > 1:
            self.drawString(36, 808, "DIE Web Analyzer • Báo Cáo Phân Tích Triage & Audit An Toàn Mã Nguồn")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, 802, 559, 802)

        # Bottom running footer on all pages
        text = f"Trang {self._pageNumber} / {page_count}"
        self.drawRightString(559, 25, text)
        self.drawString(36, 25, "Báo cáo tự động từ DIE Web Analyzer • Bảo mật & Tối mật")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 35, 559, 35)

        self.restoreState()


def fmt_size(n: int | None) -> str:
    if n is None:
        return "—"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def fmt_date(dt: datetime | None) -> str:
    if not dt:
        return "—"
    return dt.strftime("%d/%m/%Y %H:%M:%S UTC")


def esc(s: Any) -> str:
    """Escape string for ReportLab Paragraph XML."""
    if s is None:
        return ""
    return html.escape(str(s))


def generate_pdf_report(scan: Any) -> bytes:
    """Generate a clean, high-resolution PDF report for a given Scan model instance."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=pagesizes.A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=46,
        bottomMargin=46,
    )

    content_width = 595.27 - 72  # 523.27 pt

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName=BOLD_FONT,
        fontSize=17,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName=DEFAULT_FONT,
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#475569"),
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Normal"],
        fontName=BOLD_FONT,
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName=DEFAULT_FONT,
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )
    bold_style = ParagraphStyle(
        "DocBold",
        parent=body_style,
        fontName=BOLD_FONT,
    )
    mono_style = ParagraphStyle(
        "DocMono",
        parent=styles["Normal"],
        fontName=MONO_FONT,
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
    )
    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName=DEFAULT_FONT,
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#1e293b"),
    )
    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=table_cell,
        fontName=BOLD_FONT,
        textColor=colors.HexColor("#0f172a"),
    )
    table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName=BOLD_FONT,
        fontSize=8.5,
        leading=11.5,
        textColor=colors.white,
    )
    code_snippet_style = ParagraphStyle(
        "CodeSnippet",
        parent=styles["Normal"],
        fontName=MONO_FONT,
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#0284c7"),
    )

    story: list[Any] = []

    # ==================== 1. HEADER SECTION ====================
    header_data = [
        [
            Paragraph("<b>DETECT IT EASY WEB ANALYZER</b>", title_style),
            Paragraph(f"<b>MÃ MẪU: #{scan.id}</b>", ParagraphStyle("HeadId", parent=title_style, fontSize=12, alignment=2, textColor=colors.HexColor("#0284c7"))),
        ],
        [
            Paragraph("Báo Cáo Phân Tích Tệp Tin &amp; Đánh Giá An Toàn Source Code", subtitle_style),
            Paragraph(f"Thời gian xuất: {datetime.utcnow().strftime('%d/%m/%Y %H:%M:%S')} UTC", ParagraphStyle("HeadTime", parent=subtitle_style, alignment=2)),
        ],
    ]
    header_table = Table(header_data, colWidths=[360, content_width - 360])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

    # ==================== 2. METADATA SECTION ====================
    story.append(Paragraph("1. Thông tin tệp tin &amp; Mã băm nhận dạng", h2_style))

    uploader_name = getattr(scan, "uploader", None) or "Admin"
    user_id_str = f" (User ID: {scan.user_id})" if scan.user_id else ""

    meta_rows = [
        [
            Paragraph("Tên tệp tin gốc", table_cell_bold),
            Paragraph(f"<b>{esc(scan.original_name)}</b>", table_cell),
            Paragraph("Người tải lên", table_cell_bold),
            Paragraph(f"{esc(uploader_name)}{user_id_str}", table_cell),
        ],
        [
            Paragraph("Kích thước tệp", table_cell_bold),
            Paragraph(fmt_size(scan.size), table_cell),
            Paragraph("Trạng thái", table_cell_bold),
            Paragraph(f"<b>{esc(scan.status).upper()}</b>", table_cell),
        ],
        [
            Paragraph("Thời gian tải lên", table_cell_bold),
            Paragraph(fmt_date(scan.created_at), table_cell),
            Paragraph("Thời gian hoàn tất", table_cell_bold),
            Paragraph(fmt_date(scan.completed_at), table_cell),
        ],
        [
            Paragraph("Mã băm MD5", table_cell_bold),
            Paragraph(esc(scan.md5 or "—"), mono_style),
            Paragraph("Mã băm SHA-1", table_cell_bold),
            Paragraph(esc(scan.sha1 or "—"), mono_style),
        ],
        [
            Paragraph("Mã băm SHA-256", table_cell_bold),
            Paragraph(esc(scan.sha256 or "—"), mono_style),
            Paragraph("", table_cell),
            Paragraph("", table_cell),
        ],
    ]
    meta_table = Table(meta_rows, colWidths=[105, 160, 105, content_width - 370])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # Parse scan result
    result_dict = scan.result or {}
    archive_info = result_dict.get("archive")
    source_eval = result_dict.get("source_evaluation")
    die_info = result_dict.get("die") or {}
    detects = die_info.get("detects") or result_dict.get("detects") or []

    # ==================== 3. EXECUTIVE SUMMARY ====================
    story.append(Paragraph("2. Đánh giá tổng quan mức độ rủi ro", h2_style))

    risk_level = (source_eval.get("risk_level") if source_eval else "CLEAN") or "CLEAN"
    risk_score = source_eval.get("risk_score") if source_eval else 0
    risk_summary = source_eval.get("summary") if source_eval else "Tệp nhị phân phân tích hoàn tất bởi Detect It Easy."

    bg_map = {
        "CRITICAL": colors.HexColor("#fef2f2"),
        "HIGH": colors.HexColor("#fff7ed"),
        "MEDIUM": colors.HexColor("#fefce8"),
        "LOW": colors.HexColor("#f0f9ff"),
        "CLEAN": colors.HexColor("#f0fdf4"),
    }
    border_map = {
        "CRITICAL": colors.HexColor("#dc2626"),
        "HIGH": colors.HexColor("#ea580c"),
        "MEDIUM": colors.HexColor("#ca8a04"),
        "LOW": colors.HexColor("#0284c7"),
        "CLEAN": colors.HexColor("#16a34a"),
    }

    counts = source_eval.get("findings_count", {}) if source_eval else {}
    crit_c = counts.get("critical", 0)
    high_c = counts.get("high", 0)
    med_c = counts.get("medium", 0)
    low_c = counts.get("low", 0)

    summary_html = f"""
    <font color="{border_map.get(risk_level, colors.black).hexval()}"><b>MỨC ĐỘ RỦI RO: {esc(risk_level)}</b> (Điểm rủi ro: {risk_score}/100)</font><br/>
    {esc(risk_summary)}<br/>
    <font size="8" color="#475569">
    Phát hiện: <font color="#dc2626"><b>{crit_c} Nghiêm trọng (Critical)</b></font> &bull;
    <font color="#ea580c"><b>{high_c} Rủi ro cao (High)</b></font> &bull;
    <font color="#ca8a04"><b>{med_c} Trung bình (Medium)</b></font> &bull;
    <font color="#0284c7"><b>{low_c} Thấp (Low)</b></font>
    </font>
    """
    summary_table = Table([[Paragraph(summary_html, body_style)]], colWidths=[content_width])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg_map.get(risk_level, colors.white)),
        ("BOX", (0, 0), (-1, -1), 1.5, border_map.get(risk_level, colors.HexColor("#cbd5e1"))),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 12))

    # ==================== 4. DETECT IT EASY RESULTS ====================
    story.append(Paragraph("3. Kết quả nhận diện Detect It Easy (DIE)", h2_style))

    if detects:
        die_table_data = [
            [
                Paragraph("LOẠI NHẬN DIỆN", table_header),
                Paragraph("TÊN (NAME)", table_header),
                Paragraph("PHIÊN BẢN (VERSION)", table_header),
                Paragraph("THÔNG TIN BỔ SUNG", table_header),
            ]
        ]
        for d in detects:
            filetype = d.get("filetype", "—")
            for v in d.get("values", []):
                val_type = v.get("type", "—")
                val_name = v.get("name", "—")
                val_ver = v.get("version", "—")
                val_info = v.get("info", "—")
                die_table_data.append([
                    Paragraph(f"<b>{esc(filetype)}</b><br/><font color='#64748b' size='7'>{esc(val_type)}</font>", table_cell),
                    Paragraph(f"<b>{esc(val_name)}</b>", table_cell),
                    Paragraph(esc(val_ver), table_cell),
                    Paragraph(esc(val_info), table_cell),
                ])

        die_table = Table(die_table_data, colWidths=[120, 150, 95, content_width - 365])
        die_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(die_table)
    else:
        story.append(Paragraph("<i>Không phát hiện đặc trưng nhị phân hoặc packer cụ thể bởi Detect It Easy.</i>", body_style))
    story.append(Spacer(1, 12))

    # ==================== 5. ARCHIVE DETAILS (IF ARCHIVE) ====================
    if archive_info and archive_info.get("is_archive"):
        story.append(Paragraph(f"4. Phân tích tệp nén ({esc(archive_info.get('archive_type', '').upper())})", h2_style))
        arc_summary_text = (
            f"Tổng số tệp tin giải nén: <b>{archive_info.get('total_files', 0)}</b> &bull; "
            f"Dung lượng sau giải nén: <b>{fmt_size(archive_info.get('uncompressed_size', 0))}</b>"
        )
        if archive_info.get("warning"):
            arc_summary_text += f"<br/><font color='#ea580c'><b>Cảnh báo:</b> {esc(archive_info['warning'])}</font>"
        story.append(Paragraph(arc_summary_text, body_style))
        story.append(Spacer(1, 6))

        arc_files = archive_info.get("files", [])
        if arc_files:
            arc_table_data = [
                [
                    Paragraph("ĐƯỜNG DẪN TRONG ARCHIVE", table_header),
                    Paragraph("PHÂN LOẠI", table_header),
                    Paragraph("DUNG LƯỢNG", table_header),
                    Paragraph("DIE DETECTS (NẾU CÓ)", table_header),
                ]
            ]
            for af in arc_files[:40]:  # limit to first 40 files in PDF table to keep document clean
                die_detect_str = "—"
                if af.get("die_detects"):
                    first_det = af["die_detects"][0]
                    v_str = ", ".join([v.get("name", "") for v in first_det.get("values", [])[:2]])
                    die_detect_str = f"{first_det.get('filetype', '')}: {v_str}"

                arc_table_data.append([
                    Paragraph(esc(af.get("path")), mono_style),
                    Paragraph(esc(af.get("category", "")).upper(), table_cell),
                    Paragraph(fmt_size(af.get("size")), table_cell),
                    Paragraph(esc(die_detect_str), table_cell),
                ])

            arc_table = Table(arc_table_data, colWidths=[230, 75, 75, content_width - 380])
            arc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]))
            story.append(arc_table)
            if len(arc_files) > 40:
                story.append(Paragraph(f"<i>... và {len(arc_files) - 40} tệp tin khác. Xem chi tiết trên Web UI.</i>", body_style))
        story.append(Spacer(1, 12))

    # ==================== 6. SOURCE CODE SECURITY AUDIT ====================
    if source_eval and source_eval.get("is_source_project"):
        sec_num = "5" if (archive_info and archive_info.get("is_archive")) else "4"
        story.append(Paragraph(f"{sec_num}. Đánh giá bảo mật mã nguồn (Source Code Audit)", h2_style))

        # Language distribution
        langs = source_eval.get("languages", [])
        if langs:
            lang_str = " &bull; ".join([f"<b>{esc(l.get('name'))}</b> ({l.get('files')} file, {l.get('lines')} dòng - {l.get('percentage')}%)" for l in langs])
            story.append(Paragraph(f"Ngôn ngữ phát hiện: {lang_str}", body_style))
            story.append(Spacer(1, 6))

        findings = source_eval.get("findings", [])
        if findings:
            story.append(Paragraph(f"Danh sách phát hiện bảo mật ({len(findings)} vấn đề):", bold_style))
            story.append(Spacer(1, 6))

            sev_colors = {
                "CRITICAL": colors.HexColor("#dc2626"),
                "HIGH": colors.HexColor("#ea580c"),
                "MEDIUM": colors.HexColor("#ca8a04"),
                "LOW": colors.HexColor("#0284c7"),
            }
            sev_bg = {
                "CRITICAL": colors.HexColor("#fef2f2"),
                "HIGH": colors.HexColor("#fff7ed"),
                "MEDIUM": colors.HexColor("#fefce8"),
                "LOW": colors.HexColor("#f0f9ff"),
            }

            for idx, f in enumerate(findings[:50], 1):  # Cap at 50 findings in PDF
                sev = f.get("severity", "LOW")
                card_header = f"""
                <b>#{idx}. [{esc(sev)}] {esc(f.get('title'))}</b> ({esc(f.get('category'))} - Mã: {esc(f.get('rule_id'))})
                """
                card_meta = f"Vị trí: <b>{esc(f.get('file'))}:{f.get('line')}</b>"
                card_desc = esc(f.get("description", ""))

                snippet_text = f.get("snippet", "")
                snippet_p = Paragraph(f"<code>{esc(snippet_text)}</code>", code_snippet_style) if snippet_text else Paragraph("—", body_style)

                card_data = [
                    [Paragraph(card_header, ParagraphStyle("FH", parent=bold_style, textColor=sev_colors.get(sev, colors.black), fontSize=9.5))],
                    [Paragraph(card_meta, table_cell)],
                    [Paragraph(card_desc, body_style)],
                    [snippet_p],
                ]
                card_table = Table(card_data, colWidths=[content_width])
                card_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), sev_bg.get(sev, colors.white)),
                    ("BOX", (0, 0), (-1, -1), 1, sev_colors.get(sev, colors.HexColor("#cbd5e1"))),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]))
                story.append(KeepTogether(card_table))
                story.append(Spacer(1, 6))

            if len(findings) > 50:
                story.append(Paragraph(f"<i>... và còn {len(findings) - 50} phát hiện khác. Vui lòng xem toàn bộ trên giao diện DIE Web GUI.</i>", body_style))
        else:
            story.append(Paragraph("<i>Không phát hiện lỗ hổng hoặc dấu hiệu bất thường trong mã nguồn.</i>", body_style))

    # Build PDF document
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()

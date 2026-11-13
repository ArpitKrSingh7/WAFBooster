"""
Generate Professional Widescreen PowerPoint Presentation for WAFBooster.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def create_presentation():
    prs = Presentation()
    # 16:9 widescreen
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Color Palette
    C_NAVY = RGBColor(15, 23, 42)       # #0F172A Dark Slate
    C_CARD_BG = RGBColor(30, 41, 59)    # #1E293B Card Background
    C_BLUE = RGBColor(37, 99, 235)      # #2563EB Primary Accent
    C_GREEN = RGBColor(16, 185, 129)    # #10B981 Success / Boosted
    C_RED = RGBColor(239, 68, 68)       # #EF4444 Danger / Baseline
    C_WHITE = RGBColor(255, 255, 255)
    C_MUTED = RGBColor(148, 163, 184)   # #94A3B8 Secondary Text
    C_LIGHT_BG = RGBColor(248, 250, 252) # #F8FAFC
    C_BORDER = RGBColor(51, 65, 85)

    def set_slide_background(slide, color):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = color
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, category_text="WAFBOOSTER • TECHNICAL DEFENSE"):
        # Category Badge
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.4))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.size = Pt(10)
        p_cat.font.bold = True
        p_cat.font.color.rgb = C_BLUE

        # Main Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.8))
        tf_title = title_box.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.size = Pt(22)
        p_title.font.bold = True
        p_title.font.color.rgb = C_WHITE

    # -------------------------------------------------------------
    # SLIDE 1: Title Slide (Dark Theme)
    # -------------------------------------------------------------
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1, C_NAVY)

    # Accent top border
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, Inches(0.12))
    bar.fill.solid()
    bar.fill.fore_color.rgb = C_BLUE
    bar.line.fill.background()

    # Title card
    tbox = s1.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(11.333), Inches(3.5))
    tf1 = tbox.text_frame
    tf1.word_wrap = True

    p0 = tf1.paragraphs[0]
    p0.text = "IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING (TDSC 2025)"
    p0.font.size = Pt(12)
    p0.font.bold = True
    p0.font.color.rgb = C_BLUE
    p0.space_after = Pt(14)

    p1 = tf1.add_paragraph()
    p1.text = "WAFBOOSTER"
    p1.font.size = Pt(40)
    p1.font.bold = True
    p1.font.color.rgb = C_WHITE
    p1.space_after = Pt(8)

    p2 = tf1.add_paragraph()
    p2.text = "Automatic Boosting of WAF Security Against Mutated Malicious Payloads"
    p2.font.size = Pt(20)
    p2.font.color.rgb = C_MUTED
    p2.space_after = Pt(24)

    p3 = tf1.add_paragraph()
    p3.text = "Full End-to-End Testbed Implementation, Shadow Model Tuning, Algorithm 1 & 2 Synthesis, and Live Container Fortification"
    p3.font.size = Pt(13)
    p3.font.color.rgb = RGBColor(203, 213, 225)

    # Footer Card
    fbox = s1.shapes.add_textbox(Inches(1.0), Inches(5.8), Inches(11.333), Inches(1.0))
    tff = fbox.text_frame
    pf = tff.paragraphs[0]
    pf.text = "Local Environment: Docker Compose (OWASP ModSecurity CRS v3 + Flask) • PyTorch GPU (RTX 4050) • Zero False Rejections Validated"
    pf.font.size = Pt(11)
    pf.font.color.rgb = C_MUTED

    # -------------------------------------------------------------
    # SLIDE 2: Problem Statement & Motivation
    # -------------------------------------------------------------
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2, C_NAVY)
    add_header(s2, "The Core Dilemma: WAF Security vs. Syntactic Mutations")

    # 3 Cards
    cards = [
        ("The Traditional WAF Barrier",
         "Traditional Web Application Firewalls (e.g. ModSecurity CRS) rely on manually crafted regular expressions.\n\n"
         "• Strict rules cause high False Rejections (FRR), blocking benign users.\n"
         "• Permissive rules allow syntactic evasion tactics.\n"
         "• Cannot dynamically adapt to emerging mutation operators.",
         C_RED),
        ("Adversarial Evasion Tactics",
         "Attackers employ automated mutation engines (e.g., WAF-A-MoLE) to bypass regex rules without losing SQL semantics:\n\n"
         "• Whitespace substitution (/**/, %20, tabs)\n"
         "• Case randomization (SeLeCt, uNiOn)\n"
         "• Inline comments and tautologies (OR 2>1, 1=1)\n"
         "• Hex & integer encodings (0x31=0x31)",
         C_BLUE),
        ("The WAFBooster Solution",
         "A closed-loop, self-supervised defensive framework that:\n\n"
         "1. Simulates WAF behavior via a Shadow CNN.\n"
         "2. Synthesizes evasive attack variants with a GRU.\n"
         "3. Discards malformed mutants via Levenshtein editing.\n"
         "4. Synthesizes optimal ModSecurity CRS rules with Zero False Rejections.",
         C_GREEN)
    ]

    for i, (ctitle, cdesc, ccolor) in enumerate(cards):
        left = Inches(0.8 + i * 3.95)
        top = Inches(1.8)
        w = Inches(3.75)
        h = Inches(4.8)

        card = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, w, h)
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = ccolor
        card.line.width = Pt(1.5)

        tb = s2.shapes.add_textbox(left + Inches(0.25), top + Inches(0.25), w - Inches(0.5), h - Inches(0.5))
        tf = tb.text_frame
        tf.word_wrap = True

        p = tf.paragraphs[0]
        p.text = ctitle
        p.font.size = Pt(15)
        p.font.bold = True
        p.font.color.rgb = ccolor
        p.space_after = Pt(12)

        for line in cdesc.split("\n"):
            p_line = tf.add_paragraph()
            p_line.text = line
            p_line.font.size = Pt(11)
            p_line.font.color.rgb = C_WHITE if line.startswith("•") or line.startswith("1") or line.startswith("2") or line.startswith("3") or line.startswith("4") else C_MUTED
            p_line.space_after = Pt(4)

    # -------------------------------------------------------------
    # SLIDE 3: Architecture & Pipeline
    # -------------------------------------------------------------
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3, C_NAVY)
    add_header(s3, "WAFBooster 4-Stage Architectural Pipeline")

    steps = [
        ("1. Shadow Model Builder", "Section III-B",
         "• Word2Vec CBOW (128-dim embeddings)\n• ShadowCNN: Conv1d -> MaxPool -> FC\n• Accurately mimics live WAF decisions\n• Tuned lr=0.003, best-val checkpointing\n• Test Acc: 96.69%, TRR: 98.90%", C_BLUE),
        ("2. Payload Generator", "Section III-C",
         "• Self-supervised Recurrent Neural Net\n• GRU units = 256, Dropout = 0.3\n• Next-token prediction on attack corpus\n• Temperature-scaled autoregression (0.8)\n• Synthesizes diverse mutated SQLi variants", C_BLUE),
        ("3. Payload Corrector", "Section III-D (Alg 1)",
         "• Filters and repairs generated candidates\n• Levenshtein distance to top-5 keywords\n• Corrects near-typos (SALECT -> SELECT)\n• Length-proximity & relative guards\n• Zero semantic corruption of column names", C_BLUE),
        ("4. Signature Producer", "Section III-E (Alg 2)",
         "• 4 Scoring Functions: Delete, Replace, Head, Tail\n• Identifies critical discrimination tokens\n• Single-linkage clustering + Smith-Waterman\n• Zero-FRR filter on 1,400 benign queries\n• Auto-deploys 25 ModSecurity SecRules", C_GREEN),
    ]

    for i, (title, ref, desc, border_col) in enumerate(steps):
        left = Inches(0.8 + i * 2.95)
        top = Inches(1.8)
        w = Inches(2.8)
        h = Inches(4.8)

        card = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, w, h)
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = border_col
        card.line.width = Pt(1.5)

        tb = s3.shapes.add_textbox(left + Inches(0.2), top + Inches(0.2), w - Inches(0.4), h - Inches(0.4))
        tf = tb.text_frame
        tf.word_wrap = True

        p1 = tf.paragraphs[0]
        p1.text = title
        p1.font.size = Pt(13)
        p1.font.bold = True
        p1.font.color.rgb = C_WHITE

        p_ref = tf.add_paragraph()
        p_ref.text = ref
        p_ref.font.size = Pt(10)
        p_ref.font.bold = True
        p_ref.font.color.rgb = border_col
        p_ref.space_after = Pt(10)

        for line in desc.split("\n"):
            p_line = tf.add_paragraph()
            p_line.text = line
            p_line.font.size = Pt(10)
            p_line.font.color.rgb = RGBColor(226, 232, 240) if line.startswith("•") else C_MUTED
            p_line.space_after = Pt(3)

    # -------------------------------------------------------------
    # SLIDE 4: Experimental Setup & Dataset Pipeline
    # -------------------------------------------------------------
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4, C_NAVY)
    add_header(s4, "Experimental Testbed & Dataset Pipeline")

    # Left Column: Docker Architecture
    w_left = Inches(5.6)
    card_l = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), w_left, Inches(4.8))
    card_l.fill.solid()
    card_l.fill.fore_color.rgb = C_CARD_BG
    card_l.line.color.rgb = C_BORDER

    tb_l = s4.shapes.add_textbox(Inches(1.0), Inches(2.0), w_left - Inches(0.4), Inches(4.4))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "Live Dockerized Testbed Architecture"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = C_BLUE
    p.space_after = Pt(12)

    details_l = [
        ("Target Service", "Minimal Flask App on port 5000 with GET /search?q= and POST /login endpoints."),
        ("WAF Reverse Proxy", "Official OWASP ModSecurity Core Rule Set (owasp/modsecurity-crs:nginx) on port 8080."),
        ("Paranoia Level", "Paranoia Level 1 (PL1) enabled with strict anomaly scoring engine."),
        ("Hot-Reload Capability", "Rules auto-loaded via /etc/modsecurity.d/modsecurity-override.conf and reloaded with zero downtime via nginx -s reload."),
        ("Throughput", "High-performance connection pooling client achieving ~700 req/sec with ThreadPoolExecutor.")
    ]
    for k, v in details_l:
        p_k = tf_l.add_paragraph()
        p_k.text = f"• {k}: "
        p_k.font.bold = True
        p_k.font.size = Pt(11)
        p_k.font.color.rgb = C_WHITE
        p_k.space_after = Pt(2)
        p_v = tf_l.add_paragraph()
        p_v.text = f"   {v}"
        p_v.font.size = Pt(10)
        p_v.font.color.rgb = C_MUTED
        p_v.space_after = Pt(6)

    # Right Column: Dataset Pipeline
    w_right = Inches(5.8)
    card_r = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.7), Inches(1.8), w_right, Inches(4.8))
    card_r.fill.solid()
    card_r.fill.fore_color.rgb = C_CARD_BG
    card_r.line.color.rgb = C_BORDER

    tb_r = s4.shapes.add_textbox(Inches(6.9), Inches(2.0), w_right - Inches(0.4), Inches(4.4))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p_r = tf_r.paragraphs[0]
    p_r.text = "Dataset Stratification & Class Balancing"
    p_r.font.size = Pt(15)
    p_r.font.bold = True
    p_r.font.color.rgb = C_GREEN
    p_r.space_after = Pt(12)

    details_r = [
        ("CSIC 2010 Benign Traffic", "Extracted 42,000 queries from normal e-commerce traffic, downsampled to 2,000 for balanced representative evaluation."),
        ("Malicious Seeds & Mutation", "30 canonical SQLi seeds mutated using WAF-A-MoLE operators (case swap, inline comments, integer encoding) -> 614 distinct attack variants."),
        ("Ground Truth Labeling", "All payloads queried against live ModSecurity WAF to obtain genuine empirical labels (waf_label)."),
        ("Train / Val / Test Split", "70% Train (1,829 rows), 15% Val (392 rows), 15% Held-Out Test (393 rows: 300 benign, 93 malicious)."),
        ("Reproducibility", "Fixed random_state=42 and deterministic seedings throughout.")
    ]
    for k, v in details_r:
        p_k = tf_r.add_paragraph()
        p_k.text = f"• {k}: "
        p_k.font.bold = True
        p_k.font.size = Pt(11)
        p_k.font.color.rgb = C_WHITE
        p_k.space_after = Pt(2)
        p_v = tf_r.add_paragraph()
        p_v.text = f"   {v}"
        p_v.font.size = Pt(10)
        p_v.font.color.rgb = C_MUTED
        p_v.space_after = Pt(6)

    # -------------------------------------------------------------
    # SLIDE 5: Deep Dive: ShadowCNN & Corrector Bug Fix
    # -------------------------------------------------------------
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5, C_NAVY)
    add_header(s5, "Model Tuning & Algorithm 1 Semantic Bug Fix")

    card_5l = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8))
    card_5l.fill.solid()
    card_5l.fill.fore_color.rgb = C_CARD_BG
    card_5l.line.color.rgb = C_BORDER

    tb_5l = s5.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.2), Inches(4.4))
    tf_5l = tb_5l.text_frame
    tf_5l.word_wrap = True
    p = tf_5l.paragraphs[0]
    p.text = "ShadowCNN Hyperparameter Tuning"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_BLUE
    p.space_after = Pt(10)

    cnn_notes = [
        "Paper Hyperparameters: lr = 0.05, batch_size = 512.",
        "Observation on Small Dataset: lr = 0.05 caused severe validation accuracy oscillations (swings between 84% and 93%).",
        "Retuning Strategy: lr tested across {0.001, 0.003, 0.005, 0.01}. Optimal stability achieved at lr = 0.003.",
        "Best-Checkpoint Tracking: Implemented deepcopy tracking of peak validation accuracy (epoch 32) instead of saving the noisy final epoch.",
        "Final Performance: 96.69% Test Accuracy, 98.90% TRR, 96.03% TAR."
    ]
    for n in cnn_notes:
        p_n = tf_5l.add_paragraph()
        p_n.text = f"• {n}"
        p_n.font.size = Pt(10)
        p_n.font.color.rgb = C_WHITE if "Final" in n or "Optimal" in n else C_MUTED
        p_n.space_after = Pt(6)

    card_5r = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.7), Inches(1.8), Inches(5.8), Inches(4.8))
    card_5r.fill.solid()
    card_5r.fill.fore_color.rgb = C_CARD_BG
    card_5r.line.color.rgb = C_RED

    tb_5r = s5.shapes.add_textbox(Inches(6.9), Inches(2.0), Inches(5.4), Inches(4.4))
    tf_5r = tb_5r.text_frame
    tf_5r.word_wrap = True
    p = tf_5r.paragraphs[0]
    p.text = "Algorithm 1 Semantic Destruction Bug Fix"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_RED
    p.space_after = Pt(10)

    bug_notes = [
        "The Bug: Short keywords ('OR', '--') coincidentally fell into the Levenshtein (lower, upper] edit-distance window (4-8) of long column identifiers purely due to length difference.",
        "Catastrophic Rewrite: 'username' became 'SELECT' and 'password' became 'OR'. This broke SQL semantics completely.",
        "Guard 1 (Length-Proximity): Require |len(token) - len(closest_kw)| <= 2.",
        "Guard 2 (Relative Edit Distance): Require edit distance < max(len(token), len(closest_kw)) / 2 to prevent coincidental matching.",
        "Result: 0 false corrections. 313 valid candidates safely passed to Signature Producer without destroying column identifiers."
    ]
    for n in bug_notes:
        p_n = tf_5r.add_paragraph()
        p_n.text = f"• {n}"
        p_n.font.size = Pt(10)
        p_n.font.color.rgb = C_WHITE if "Result" in n or "Guard" in n else C_MUTED
        p_n.space_after = Pt(6)

    # -------------------------------------------------------------
    # SLIDE 6: Chart Slide: Model Retuning & Ablation
    # -------------------------------------------------------------
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6, C_NAVY)
    add_header(s6, "Empirical Validation: ShadowCNN Retuning & Rule Ablation")

    chart2_path = "/home/arpit/is/results_ablation_and_cnn.png"
    if os.path.exists(chart2_path):
        s6.shapes.add_picture(chart2_path, Inches(0.8), Inches(1.7), width=Inches(11.7))

    # -------------------------------------------------------------
    # SLIDE 7: Signature Producer (Algorithm 2)
    # -------------------------------------------------------------
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7, C_NAVY)
    add_header(s7, "Algorithm 2: Discrimination Scoring & Rule Synthesis")

    cards_7 = [
        ("Four Scoring Functions",
         "Measures the exact impact of token x_i on WAF discrimination:\n\n"
         "• Delete Score (DS):\n  f(x_1..x_n) - f(x without x_i)\n"
         "• Replace Score (RS):\n  f(x_1..x_n) - f(x with x_i='unknown')\n"
         "• Head Score (HS):\n  f(x_1..x_i) - f(x_1..x_{i-1})\n"
         "• Tail Score (TS):\n  f(x_i..x_n) - f(x_{i+1}..x_n)\n\n"
         "Combined Score: Score[i] = DS + RS + HS + TS",
         C_BLUE),
        ("Clustering & Alignment",
         "Finds consensus malicious subsequences across payloads:\n\n"
         "• Levenshtein Clustering:\n  Groups similar important tokens into clusters with threshold = 2.0.\n"
         "• Smith-Waterman Alignment:\n  Local sequence alignment with match = +1.0, gap penalty = -0.8.\n"
         "• Subsequence Extraction:\n  Extracts common patterns (e.g. 'sLe', 'UNION', 'password', 'users').",
         C_BLUE),
        ("Zero-FRR Enforcement",
         "Strict paper constraint: Zero False Rejections on legitimate traffic:\n\n"
         "• 1,400 CSIC Benign Samples:\n  Every candidate regex is verified against true benign queries.\n"
         "• Zero-Tolerance Filter:\n  Any rule matching even 1 benign sample is rejected or constrained.\n"
         "• Word Boundaries:\n  Enforced \\b boundaries on alpha keywords to avoid substring collision (e.g. 'New York' vs 'OR').",
         C_GREEN)
    ]

    for i, (ctitle, cdesc, ccolor) in enumerate(cards_7):
        left = Inches(0.8 + i * 3.95)
        top = Inches(1.8)
        w = Inches(3.75)
        h = Inches(4.8)

        card = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, w, h)
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = ccolor
        card.line.width = Pt(1.5)

        tb = s7.shapes.add_textbox(left + Inches(0.25), top + Inches(0.25), w - Inches(0.5), h - Inches(0.5))
        tf = tb.text_frame
        tf.word_wrap = True

        p = tf.paragraphs[0]
        p.text = ctitle
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = ccolor
        p.space_after = Pt(10)

        for line in cdesc.split("\n"):
            p_line = tf.add_paragraph()
            p_line.text = line
            p_line.font.size = Pt(10)
            p_line.font.color.rgb = C_WHITE if line.startswith("•") or line.startswith("Combined") else C_MUTED
            p_line.space_after = Pt(3)

    # -------------------------------------------------------------
    # SLIDE 8: Chart Slide: Held-Out Generalization
    # -------------------------------------------------------------
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8, C_NAVY)
    add_header(s8, "Held-Out Generalization: Baseline vs. Boosted WAF")

    chart1_path = "/home/arpit/is/results_generalization_chart.png"
    if os.path.exists(chart1_path):
        s8.shapes.add_picture(chart1_path, Inches(2.6), Inches(1.7), width=Inches(8.1))

    # -------------------------------------------------------------
    # SLIDE 9: Generalization Table & Quantitative Results
    # -------------------------------------------------------------
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9, C_NAVY)
    add_header(s9, "Comprehensive Out-of-Sample Evaluation Table")

    # Table
    rows = 4
    cols = 6
    left = Inches(0.8)
    top = Inches(1.8)
    width = Inches(11.7)
    height = Inches(2.5)

    table_shape = s9.shapes.add_table(rows, cols, left, top, width, height)
    table = table_shape.table

    headers = ["Dataset Split", "Evaluation Metric", "Total Samples", "Baseline WAF (CRS PL1)", "Boosted WAF (+Rules)", "Improvement (Δ)"]
    for j, h in enumerate(headers):
        cell = table.cell(0, j)
        cell.fill.solid()
        cell.fill.fore_color.rgb = C_BLUE
        cell.text = h
        p = cell.text_frame.paragraphs[0]
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = C_WHITE

    data = [
        ["Held-Out Malicious (test.csv)", "TRR (True Rejection)", "93", "91 / 93 (97.85%)", "93 / 93 (100.00%)", "+2.15%"],
        ["Held-Out Benign (test.csv)", "TAR (True Acceptance)", "300", "300 / 300 (100.00%)", "300 / 300 (100.00%)", "+0.00% (0% FRR)"],
        ["Novel Generated Attacks (GRU)", "TRR (True Rejection)", "94", "48 / 94 (51.06%)", "93 / 94 (98.94%)", "+47.87% 🔥"],
    ]

    for i, row in enumerate(data):
        for j, val in enumerate(row):
            cell = table.cell(i + 1, j)
            cell.fill.solid()
            cell.fill.fore_color.rgb = C_CARD_BG if i % 2 == 0 else RGBColor(24, 33, 47)
            cell.text = val
            p = cell.text_frame.paragraphs[0]
            p.font.size = Pt(11)
            p.font.color.rgb = C_GREEN if "+" in val or "100" in val else C_WHITE

    # Key Takeaways Box below table
    card_k = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(4.7), Inches(11.7), Inches(1.9))
    card_k.fill.solid()
    card_k.fill.fore_color.rgb = C_CARD_BG
    card_k.line.color.rgb = C_GREEN
    card_k.line.width = Pt(1.5)

    tb_k = s9.shapes.add_textbox(Inches(1.0), Inches(4.8), Inches(11.3), Inches(1.7))
    tf_k = tb_k.text_frame
    tf_k.word_wrap = True

    p = tf_k.paragraphs[0]
    p.text = "Key Defense & Viva Takeaways"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = C_GREEN
    p.space_after = Pt(4)

    pts = [
        "Massive Generalization Gain: The boosted WAF increased defense against unseen GRU mutants from 51.06% to 98.94% (+47.87%), proving the signatures generalize far beyond the initial seeds.",
        "Zero False Rejection Guarantee: Across 300 held-out benign queries and 1,400 training benign queries, the boosted WAF achieved exactly 0.00% FRR (100% TAR).",
        "Autonomous Learning Power: The ablation study proved that 85.9% of bypass coverage stems purely from Smith-Waterman sequence alignment without any manual rules."
    ]
    for pt in pts:
        p_pt = tf_k.add_paragraph()
        p_pt.text = f"• {pt}"
        p_pt.font.size = Pt(10)
        p_pt.font.color.rgb = C_WHITE
        p_pt.space_after = Pt(3)

    # -------------------------------------------------------------
    # SLIDE 10: Conclusion & Summary
    # -------------------------------------------------------------
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10, C_NAVY)
    add_header(s10, "Summary of Contributions & Deliverables")

    cards_10 = [
        ("Complete System Implementation",
         "• Built a full local Docker testbed with live OWASP ModSecurity CRS & Flask backend.\n"
         "• Implemented all four core modules of WAFBooster (IEEE TDSC 2025).\n"
         "• Discovered and fixed the critical semantic destruction bug in Algorithm 1.\n"
         "• Tuned ShadowCNN learning rate and implemented best-validation checkpointing.",
         C_BLUE),
        ("Rigorous Generalization Testing",
         "• Avoided circular evaluation by validating on completely held-out test splits.\n"
         "• Generated 94 novel GRU attacks using unseen seed tokens and distinct random seeds.\n"
         "• Demonstrated +47.87% improvement in TRR against genuinely unseen attack variants.\n"
         "• Proved 100% TAR (0% False Rejection Rate) on legitimate traffic.",
         C_GREEN),
        ("Production & Defense Readiness",
         "• Deployed 25 ModSecurity CRS SecRules hot-reloaded into live Nginx containers.\n"
         "• Replicated the paper's core claims with empirical proofs.\n"
         "• High-resolution vector charts & reproducible Python evaluation scripts included.\n"
         "• Ideal foundation for presentation, paper defense, or enterprise WAF deployment.",
         C_BLUE),
    ]

    for i, (ctitle, cdesc, ccolor) in enumerate(cards_10):
        left = Inches(0.8 + i * 3.95)
        top = Inches(1.8)
        w = Inches(3.75)
        h = Inches(4.8)

        card = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, w, h)
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = ccolor
        card.line.width = Pt(1.5)

        tb = s10.shapes.add_textbox(left + Inches(0.25), top + Inches(0.25), w - Inches(0.5), h - Inches(0.5))
        tf = tb.text_frame
        tf.word_wrap = True

        p = tf.paragraphs[0]
        p.text = ctitle
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = ccolor
        p.space_after = Pt(12)

        for line in cdesc.split("\n"):
            p_line = tf.add_paragraph()
            p_line.text = line
            p_line.font.size = Pt(10)
            p_line.font.color.rgb = C_WHITE if line.startswith("•") else C_MUTED
            p_line.space_after = Pt(4)

    # Save presentation
    output_path = "/home/arpit/is/WAFBooster_Defense_Presentation.pptx"
    prs.save(output_path)
    print(f"Presentation saved successfully to: {output_path}")

if __name__ == "__main__":
    create_presentation()

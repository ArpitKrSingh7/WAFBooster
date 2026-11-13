"""
Generate the Gold-Standard 14-Slide Widescreen PowerPoint Presentation for WAFBooster.
Divided across 3 team members: Abdur Rahim, Faraz Nezami, Arpit Kumar Singh.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def create_14_slide_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Theme Colors
    C_NAVY = RGBColor(15, 23, 42)        # #0F172A
    C_CARD_BG = RGBColor(30, 41, 59)     # #1E293B
    C_BLUE = RGBColor(37, 99, 235)       # #2563EB
    C_GREEN = RGBColor(16, 185, 129)     # #10B981
    C_RED = RGBColor(239, 68, 68)        # #EF4444
    C_WHITE = RGBColor(255, 255, 255)
    C_MUTED = RGBColor(148, 163, 184)    # #94A3B8
    C_BORDER = RGBColor(51, 65, 85)

    def set_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = C_NAVY
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, presenter_text, category_text="WAFBOOSTER • IEEE TDSC 2025 DEFENSE"):
        # Header Badge
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.35), Inches(8.0), Inches(0.35))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.size = Pt(9.5)
        p_cat.font.bold = True
        p_cat.font.color.rgb = C_BLUE

        # Presenter Badge (Right-aligned)
        pres_box = slide.shapes.add_textbox(Inches(7.5), Inches(0.35), Inches(5.0), Inches(0.35))
        tf_pres = pres_box.text_frame
        tf_pres.word_wrap = True
        p_pres = tf_pres.paragraphs[0]
        p_pres.text = f"PRESENTER: {presenter_text.upper()}"
        p_pres.font.size = Pt(9.5)
        p_pres.font.bold = True
        p_pres.font.color.rgb = C_GREEN

        # Main Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.65), Inches(11.7), Inches(0.8))
        tf_title = title_box.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.size = Pt(21)
        p_title.font.bold = True
        p_title.font.color.rgb = C_WHITE

    # -------------------------------------------------------------
    # SLIDE 1: Title & Team Overview (Abdur Rahim)
    # -------------------------------------------------------------
    s1 = prs.slides.add_slide(blank_layout)
    set_bg(s1)

    top_bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, Inches(0.12))
    top_bar.fill.solid()
    top_bar.fill.fore_color.rgb = C_BLUE
    top_bar.line.fill.background()

    tb1 = s1.shapes.add_textbox(Inches(1.0), Inches(1.5), Inches(11.333), Inches(3.2))
    tf1 = tb1.text_frame
    tf1.word_wrap = True

    p0 = tf1.paragraphs[0]
    p0.text = "INFORMATION SECURITY COURSE PROJECT • IEEE TDSC 2025 IMPLEMENTATION"
    p0.font.size = Pt(11)
    p0.font.bold = True
    p0.font.color.rgb = C_BLUE
    p0.space_after = Pt(10)

    p1 = tf1.add_paragraph()
    p1.text = "WAFBOOSTER"
    p1.font.size = Pt(38)
    p1.font.bold = True
    p1.font.color.rgb = C_WHITE

    p2 = tf1.add_paragraph()
    p2.text = "Automatic Boosting of WAF Security Against Mutated Malicious Payloads"
    p2.font.size = Pt(20)
    p2.font.color.rgb = C_MUTED
    p2.space_after = Pt(18)

    p3 = tf1.add_paragraph()
    p3.text = "A complete engineering realization featuring live Dockerized OWASP ModSecurity CRS, ShadowCNN tuning,\nGRU adversarial mutations, semantic corrector bug repair, and Algorithm 2 hot-reload fortification."
    p3.font.size = Pt(12)
    p3.font.color.rgb = RGBColor(203, 213, 225)

    # 3 Team Member Badges at Bottom
    members = [
        ("Abdur Rahim (CS23I1019)", "Milestones 1–2", "Architecture, Testbed & Dataset Engineering", C_BLUE),
        ("Faraz Nezami (CS23I1031)", "Milestones 3–4", "ShadowCNN, GRU & Corrector Bug Fix", C_BLUE),
        ("Arpit Kumar Singh (CS23I1022)", "Milestones 5–6", "Algorithm 2, Ablation & Generalization", C_GREEN),
    ]
    for i, (mname, mmile, mrole, mcolor) in enumerate(members):
        left = Inches(1.0 + i * 3.85)
        top = Inches(5.2)
        w = Inches(3.6)
        h = Inches(1.6)
        card = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, w, h)
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = mcolor
        card.line.width = Pt(1.5)

        tb_m = s1.shapes.add_textbox(left + Inches(0.2), top + Inches(0.15), w - Inches(0.4), h - Inches(0.3))
        tf_m = tb_m.text_frame
        tf_m.word_wrap = True
        p_m1 = tf_m.paragraphs[0]
        p_m1.text = mname
        p_m1.font.size = Pt(12)
        p_m1.font.bold = True
        p_m1.font.color.rgb = C_WHITE

        p_m2 = tf_m.add_paragraph()
        p_m2.text = mmile
        p_m2.font.size = Pt(10)
        p_m2.font.bold = True
        p_m2.font.color.rgb = mcolor

        p_m3 = tf_m.add_paragraph()
        p_m3.text = mrole
        p_m3.font.size = Pt(9.5)
        p_m3.font.color.rgb = C_MUTED

    # -------------------------------------------------------------
    # SLIDE 2: Problem Statement (Abdur Rahim)
    # -------------------------------------------------------------
    s2 = prs.slides.add_slide(blank_layout)
    set_bg(s2)
    add_header(s2, "The Fragility of Static Rule-Based Web Application Firewalls", "Abdur Rahim (CS23I1019)")

    cards_2 = [
        ("The Traditional WAF Tradeoff",
         "Web Application Firewalls inspect incoming HTTP traffic via regular expressions.\n\n"
         "• Strict policies increase the False Rejection Rate (FRR), blocking benign users.\n"
         "• Relaxed policies leave gaping holes for malicious evasion.\n"
         "• OWASP CRS Paranoia Level 1 uses cumulative anomaly scoring (threshold >= 5), missing low-scoring stealthy evasions.",
         C_RED),
        ("Adversarial Evasion Techniques",
         "Automated mutation engines (WAF-A-MoLE) systematically perturb attack syntax while maintaining valid execution:\n\n"
         "• Whitespace Substitution: Replacing spaces with /**/, %20, or tabs.\n"
         "• Case Randomization: SeLeCt, uNiOn, FrOm.\n"
         "• Logical Rewrites: OR '1'='1' rewritten as OR 2>1 or OR 'x'='x'.\n"
         "• Hex Encoding: Bypassing string checks with 0x31=0x31.",
         C_BLUE),
        ("The Defense Gap",
         "Manual signature creation cannot keep pace with automated combinatoric mutations.\n\n"
         "• Security teams manually analyze incident logs post-breach.\n"
         "• Signatures often overfit to known samples, causing regressions on legitimate traffic.\n"
         "• Required: An automated, closed-loop system that finds bypasses and generates zero-FRR signatures.",
         C_GREEN),
    ]
    for i, (ct, cd, cc) in enumerate(cards_2):
        left = Inches(0.8 + i * 3.95)
        card = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.8), Inches(3.75), Inches(4.8))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = cc
        card.line.width = Pt(1.5)

        tb = s2.shapes.add_textbox(left + Inches(0.25), Inches(2.0), Inches(3.25), Inches(4.4))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = ct
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = cc
        p.space_after = Pt(10)
        for line in cd.split("\n"):
            pl = tf.add_paragraph()
            pl.text = line
            pl.font.size = Pt(10)
            pl.font.color.rgb = C_WHITE if line.startswith("•") else C_MUTED
            pl.space_after = Pt(3)

    # -------------------------------------------------------------
    # SLIDE 3: WAFBooster Architecture (Abdur Rahim)
    # -------------------------------------------------------------
    s3 = prs.slides.add_slide(blank_layout)
    set_bg(s3)
    add_header(s3, "WAFBooster Closed-Loop Architecture (IEEE TDSC 2025)", "Abdur Rahim (CS23I1019)")

    arch_steps = [
        ("Module 1: Shadow Model", "Section III-B",
         "• Replicates live WAF discrimination.\n• Word2Vec CBOW (128-dim).\n• ShadowCNN classifies requests as allowed or blocked.\n• Fast gradient proxy for testing.", C_BLUE),
        ("Module 2: Payload Generator", "Section III-C",
         "• Autoregressive GRU network (256 units).\n• Self-supervised next-token language model.\n• Synthesizes adversarial candidates from seed tokens (', UNION, SELECT).", C_BLUE),
        ("Module 3: Payload Corrector", "Section III-D (Alg 1)",
         "• Discards non-executable corruptions.\n• Levenshtein edit distance to top-5 keywords.\n• Corrects near-typos (SALECT -> SELECT).\n• Length-proximity guards prevent identifier mangling.", C_BLUE),
        ("Module 4: Signature Producer", "Section III-E (Alg 2)",
         "• Pinpoints high-impact tokens via 4 scoring functions (DS, RS, HS, TS).\n• Clusters tokens & runs Smith-Waterman LCS.\n• Zero-FRR benign validation gate.\n• Deploys ModSecurity CRS SecRules.", C_GREEN),
    ]
    for i, (st, sr, sd, sc) in enumerate(arch_steps):
        left = Inches(0.8 + i * 2.95)
        card = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.8), Inches(2.8), Inches(4.8))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = sc
        card.line.width = Pt(1.5)

        tb = s3.shapes.add_textbox(left + Inches(0.2), Inches(2.0), Inches(2.4), Inches(4.4))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = st
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = C_WHITE
        pref = tf.add_paragraph()
        pref.text = sr
        pref.font.size = Pt(10)
        pref.font.bold = True
        pref.font.color.rgb = sc
        pref.space_after = Pt(8)
        for line in sd.split("\n"):
            pl = tf.add_paragraph()
            pl.text = line
            pl.font.size = Pt(10)
            pl.font.color.rgb = RGBColor(226, 232, 240) if line.startswith("•") else C_MUTED
            pl.space_after = Pt(4)

    # -------------------------------------------------------------
    # SLIDE 4: Milestones 1-2: Environment & Imbalance (Abdur Rahim)
    # -------------------------------------------------------------
    s4 = prs.slides.add_slide(blank_layout)
    set_bg(s4)
    add_header(s4, "Milestones 1 & 2: Live Docker Testbed & Imbalance Remediation", "Abdur Rahim (CS23I1019)")

    # Left: Docker Architecture
    c4l = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8))
    c4l.fill.solid()
    c4l.fill.fore_color.rgb = C_CARD_BG
    c4l.line.color.rgb = C_BORDER

    tb4l = s4.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.2), Inches(4.4))
    tf4l = tb4l.text_frame
    tf4l.word_wrap = True
    p = tf4l.paragraphs[0]
    p.text = "Milestone 1: Live Docker Testbed"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_BLUE
    p.space_after = Pt(10)

    m1_points = [
        "docker-compose.yml: Two orchestrated services on internal bridge network.",
        "Backend (app.py): Minimal Python 3.11 Flask service on port 5000 with GET /search?q= and POST /login endpoints.",
        "WAF Proxy: Official owasp/modsecurity-crs:nginx on port 8080 at Paranoia Level 1 (PL1).",
        "WAF Client (waf_client.py): Connection-pooled HTTP client achieving ~700 req/s with ThreadPoolExecutor.",
        "Hot-Reload Mechanism: Custom rules loaded via /etc/modsecurity.d/modsecurity-override.conf; nginx -s reload achieves zero downtime."
    ]
    for pt in m1_points:
        pl = tf4l.add_paragraph()
        pl.text = f"• {pt}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "docker" in pt or "Hot-Reload" in pt else C_MUTED
        pl.space_after = Pt(5)

    # Right: Imbalance
    c4r = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.7), Inches(1.8), Inches(5.8), Inches(4.8))
    c4r.fill.solid()
    c4r.fill.fore_color.rgb = C_CARD_BG
    c4r.line.color.rgb = C_GREEN

    tb4r = s4.shapes.add_textbox(Inches(6.9), Inches(2.0), Inches(5.4), Inches(4.4))
    tf4r = tb4r.text_frame
    tf4r.word_wrap = True
    p = tf4r.paragraphs[0]
    p.text = "Milestone 2: Solving the 29,401:20 Imbalance"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_GREEN
    p.space_after = Pt(10)

    m2_points = [
        "The Initial Trap: Loading full CSIC 2010 raw data produced 29,401 benign queries vs. only 20 seed malicious queries (1,470:1 ratio). Neural models collapsed to predicting all-benign.",
        "WAF-A-MoLE Mutation Engine (mutate_seed): Applied 5 combinatoric operators (case swap, comments, whitespace, hex, logic) across 30 seeds -> 614 unique malicious variants.",
        "Benign Downsampling: Randomly sampled 2,000 benign queries from CSIC normal traffic (fixed seed=42).",
        "Live Ground-Truth Labeling: Evaluated all 2,614 payloads against live ModSecurity WAF.",
        "Stratified Split: 70% Train (1,829), 15% Val (392), 15% Held-Out Test (393: 300 benign, 93 malicious)."
    ]
    for pt in m2_points:
        pl = tf4r.add_paragraph()
        pl.text = f"• {pt}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Trap" in pt or "Stratified" in pt else C_MUTED
        pl.space_after = Pt(5)

    # -------------------------------------------------------------
    # SLIDE 5: Milestone 3: Shadow Model & Tokenizer (Faraz Nezami)
    # -------------------------------------------------------------
    s5 = prs.slides.add_slide(blank_layout)
    set_bg(s5)
    add_header(s5, "Milestone 3: SQL Tokenizer & ShadowCNN Builder", "Faraz Nezami (CS23I1031)")

    cards_5 = [
        ("SQL-Aware Regex Tokenizer",
         "Standard whitespace split collapses payloads into blobs (admin'-- becomes 1 token).\n\n"
         "• Custom Regex:\n  0x|--|/\\*|\\*/|['=(),;]|\\w+|[^\\s\\w'=(),;]\n"
         "• Preserves SQL Semantics:\n  admin'-- correctly tokenized into:\n  ['admin', \"'\", '--']\n"
         "• Handles encoded tokens:\n  %20, /**/, and hex literals (0x31) isolated as distinct syntactic units.",
         C_BLUE),
        ("Word2Vec CBOW Vectorizer",
         "Maps discrete SQL tokens into dense semantic vector space.\n\n"
         "• Architecture: Continuous Bag-of-Words (CBOW), window = 5, min_count = 1.\n"
         "• Embedding Dimension: 128-dim dense vector representation.\n"
         "• Aggregation: Token vectors averaged per payload via payload_to_vector().\n"
         "• Output: Consistent 128-dimensional feature vector for every payload.",
         C_BLUE),
        ("ShadowCNN Architecture",
         "PyTorch 1D Convolutional Neural Network matching paper Section III-B:\n\n"
         "• Input: (batch, 1, 128) unsqueezed vector\n"
         "• Conv1d: in=1, out=32, kernel=3, padding=1\n"
         "• Pooling & Reg: ReLU -> MaxPool1d(2) -> Dropout(0.3)\n"
         "• Fully-Connected: Linear(2048 -> 256) -> ReLU -> Linear(256 -> 2)\n"
         "• Output: Raw logits for CrossEntropyLoss",
         C_GREEN),
    ]
    for i, (ct, cd, cc) in enumerate(cards_5):
        left = Inches(0.8 + i * 3.95)
        card = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.8), Inches(3.75), Inches(4.8))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = cc
        card.line.width = Pt(1.5)

        tb = s5.shapes.add_textbox(left + Inches(0.25), Inches(2.0), Inches(3.25), Inches(4.4))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = ct
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = cc
        p.space_after = Pt(10)
        for line in cd.split("\n"):
            pl = tf.add_paragraph()
            pl.text = line
            pl.font.size = Pt(10)
            pl.font.color.rgb = C_WHITE if line.startswith("•") else C_MUTED
            pl.space_after = Pt(3)

    # -------------------------------------------------------------
    # SLIDE 6: Milestone 3: LR Tuning & Checkpointing (Faraz Nezami)
    # -------------------------------------------------------------
    s6 = prs.slides.add_slide(blank_layout)
    set_bg(s6)
    add_header(s6, "Milestone 3: Hyperparameter Retuning & Checkpointing", "Faraz Nezami (CS23I1031)")

    # Chart 2 Left embedded on Slide 6
    chart2_path = "/home/arpit/is/results_ablation_and_cnn.png"
    if os.path.exists(chart2_path):
        s6.shapes.add_picture(chart2_path, Inches(0.8), Inches(1.8), width=Inches(6.6))

    # Right side text card
    c6r = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(7.7), Inches(1.8), Inches(4.8), Inches(4.8))
    c6r.fill.solid()
    c6r.fill.fore_color.rgb = C_CARD_BG
    c6r.line.color.rgb = C_GREEN

    tb6r = s6.shapes.add_textbox(Inches(7.9), Inches(2.0), Inches(4.4), Inches(4.4))
    tf6r = tb6r.text_frame
    tf6r.word_wrap = True
    p = tf6r.paragraphs[0]
    p.text = "The Learning Rate Stability Crisis"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_GREEN
    p.space_after = Pt(10)

    lr_notes = [
        "Paper Setting (lr = 0.05): Tested on massive commercial datasets. On our 1,829-row dataset with class weights [1.0, 3.31], lr=0.05 caused violent gradient overshoot, swinging validation accuracy between 84% and 93%.",
        "Empirical Search: Evaluated lr in {0.001, 0.003, 0.005, 0.01}. lr = 0.003 provided smooth, monotonic convergence.",
        "Best-Epoch Checkpointing: Final-epoch weights frequently suffered from late-training noise. Implemented copy.deepcopy() tracking of peak validation accuracy (epoch 32).",
        "Performance Leap: Test Accuracy jumped from 86.01% to 96.69%; Test TAR jumped from 81.79% to 96.03% (TR = 98.90%)."
    ]
    for n in lr_notes:
        pl = tf6r.add_paragraph()
        pl.text = f"• {n}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Leap" in n or "Empirical" in n else C_MUTED
        pl.space_after = Pt(6)

    # -------------------------------------------------------------
    # SLIDE 7: Milestone 4: GRU Payload Generator (Faraz Nezami)
    # -------------------------------------------------------------
    s7 = prs.slides.add_slide(blank_layout)
    set_bg(s7)
    add_header(s7, "Milestone 4: Self-Supervised Adversarial Payload Generation", "Faraz Nezami (CS23I1031)")

    cards_7 = [
        ("PayloadGRU Architecture",
         "Neural language model generating sequential attack tokens:\n\n"
         "• Vocab Size: 333 unique SQL tokens + special tokens (<PAD>=0, <START>=1, <END>=2, <UNK>=3).\n"
         "• Embedding: 128-dim dense token representation.\n"
         "• Recurrent Layer: GRU with hidden_size = 256, batch_first=True.\n"
         "• Regularization: Dropout = 0.3 before Linear projection to vocab size.",
         C_BLUE),
        ("Training & Loss Convergence",
         "Self-supervised next-token prediction on 614 malicious payloads:\n\n"
         "• Objective: Predict tokens[1:] given tokens[:-1].\n"
         "• Loss: CrossEntropyLoss(ignore_index=PAD).\n"
         "• Optimizer & Schedule: Adam lr=0.001 with StepLR (halves every 10 epochs).\n"
         "• Loss Progression: Monotonically converged from 4.8837 (Epoch 1) down to 0.8642 (Epoch 50).",
         C_BLUE),
        ("Autoregressive Sampling",
         "Generating synthetic candidates to test WAF boundaries:\n\n"
         "• Seed Tokens: Initialized with canonical prefixes: [\"'\", \"1\", \"admin\", \"UNION\", \"SELECT\", \"OR\"].\n"
         "• Temperature Scaling: T = 0.8 balances syntactic coherence with mutant diversity.\n"
         "• Stopping Condition: Emits tokens until <END> or max_len=30.\n"
         "• Output: 316 unique candidate attack payloads saved.",
         C_GREEN),
    ]
    for i, (ct, cd, cc) in enumerate(cards_7):
        left = Inches(0.8 + i * 3.95)
        card = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.8), Inches(3.75), Inches(4.8))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = cc
        card.line.width = Pt(1.5)

        tb = s7.shapes.add_textbox(left + Inches(0.25), Inches(2.0), Inches(3.25), Inches(4.4))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = ct
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = cc
        p.space_after = Pt(10)
        for line in cd.split("\n"):
            pl = tf.add_paragraph()
            pl.text = line
            pl.font.size = Pt(10)
            pl.font.color.rgb = C_WHITE if line.startswith("•") else C_MUTED
            pl.space_after = Pt(3)

    # -------------------------------------------------------------
    # SLIDE 8: Milestone 4: Levenshtein Bug Fix (Faraz Nezami)
    # -------------------------------------------------------------
    s8 = prs.slides.add_slide(blank_layout)
    set_bg(s8)
    add_header(s8, "Milestone 4: The Algorithm 1 Semantic Destruction Bug & Fix", "Faraz Nezami (CS23I1031)")

    # Left: The Bug
    c8l = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8))
    c8l.fill.solid()
    c8l.fill.fore_color.rgb = C_CARD_BG
    c8l.line.color.rgb = C_RED

    tb8l = s8.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.2), Inches(4.4))
    tf8l = tb8l.text_frame
    tf8l.word_wrap = True
    p = tf8l.paragraphs[0]
    p.text = "The Algorithm 1 Bug (Semantic Destruction)"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_RED
    p.space_after = Pt(10)

    bug_points = [
        "Algorithm 1 Premise: If Levenshtein distance d in (lower, upper] (4 < d <= 8), replace token with closest keyword (SELECT, OR, UNION, FROM, --).",
        "The Vulnerability: Short keywords ('OR', '--') have edit distance 4-8 from legitimate long column names purely due to string length difference.",
        "Catastrophic Rewrite Example:\n  ' UNION SELECT username,password FROM users--\n  became:\n  ' UNION SELECT SELECT,OR FROM users--",
        "The Disaster: Column names were mangled into keywords! If defended in a viva, this would destroy technical credibility.",
        "Initial Run: Falsely corrected 65 payloads, corrupting innocent column identifiers."
    ]
    for pt in bug_points:
        pl = tf8l.add_paragraph()
        pl.text = f"• {pt}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Catastrophic" in pt or "Disaster" in pt else C_MUTED
        pl.space_after = Pt(5)

    # Right: The Fix
    c8r = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.7), Inches(1.8), Inches(5.8), Inches(4.8))
    c8r.fill.solid()
    c8r.fill.fore_color.rgb = C_CARD_BG
    c8r.line.color.rgb = C_GREEN

    tb8r = s8.shapes.add_textbox(Inches(6.9), Inches(2.0), Inches(5.4), Inches(4.4))
    tf8r = tb8r.text_frame
    tf8r.word_wrap = True
    p = tf8r.paragraphs[0]
    p.text = "Our Two-Tiered Semantic Guard Fix"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_GREEN
    p.space_after = Pt(10)

    fix_points = [
        "Guard 1 (Length-Proximity): Only allow replacement if:\n  |len(token) - len(closest_keyword)| <= 2\n(Prevents 2-char 'OR' from matching 8-char 'password').",
        "Guard 2 (Relative Edit Distance): Only allow replacement if:\n  d < max(len(token), len(closest_keyword)) / 2\n(Prevents 'username' matching 'SELECT').",
        "True Typos Corrected: Near-mutations like 'SALECT' -> 'SELECT' are preserved and repaired.",
        "Legitimate Identifiers Preserved: 'username', 'password', 'users' remain completely untouched.",
        "Clean Output: 313 valid candidates safely passed to Signature Producer; 3 malformed discarded (0% corruption)."
    ]
    for pt in fix_points:
        pl = tf8r.add_paragraph()
        pl.text = f"• {pt}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Guard" in pt or "Clean" in pt else C_MUTED
        pl.space_after = Pt(5)

    # -------------------------------------------------------------
    # SLIDE 9: Milestone 5: Algorithm 2 Token Scoring (Arpit)
    # -------------------------------------------------------------
    s9 = prs.slides.add_slide(blank_layout)
    set_bg(s9)
    add_header(s9, "Milestone 5: Algorithm 2 Discrimination Scoring & Alignment", "Arpit Kumar Singh (CS23I1022)")

    cards_9 = [
        ("Four Scoring Functions",
         "Measures the exact empirical impact of token x_i on WAF classification:\n\n"
         "• Delete Score (DS):\n  f(x_1..x_n) - f(x without x_i)\n"
         "• Replace Score (RS):\n  f(x_1..x_n) - f(x with x_i='unknown')\n"
         "• Head Score (HS):\n  f(x_1..x_i) - f(x_1..x_{i-1})\n"
         "• Tail Score (TS):\n  f(x_i..x_n) - f(x_{i+1}..x_n)\n\n"
         "Combined Score: Score[i] = DS + RS + HS + TS",
         C_BLUE),
        ("Clustering & Alignment",
         "Consolidates token patterns across 64 bypassing payloads:\n\n"
         "• Single-Linkage Clustering:\n  Groups similar important tokens by Levenshtein distance (threshold <= 2.0).\n"
         "• Smith-Waterman LCS:\n  Local alignment rewarding matches (+1.0) and penalizing gaps (gp = -0.8).\n"
         "• Subsequence Extraction:\n  Extracts recurring cores: 'sLe', 'UNION', 'password', 'users', 'SELECT'.",
         C_BLUE),
        ("Zero-FRR Validation Gate",
         "Enforcing the paper's core guarantee: No False Positives on benign traffic:\n\n"
         "• 1,400 Benign CSIC Samples:\n  Every candidate pattern evaluated against real normal requests.\n"
         "• Zero-Tolerance Filter:\n  Any rule matching even 1 benign sample is rejected or constrained.\n"
         "• Word Boundaries:\n  Added \\b boundaries to prevent substring collisions (e.g. 'New York' matching 'OR').",
         C_GREEN),
    ]
    for i, (ct, cd, cc) in enumerate(cards_9):
        left = Inches(0.8 + i * 3.95)
        card = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.8), Inches(3.75), Inches(4.8))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = cc
        card.line.width = Pt(1.5)

        tb = s9.shapes.add_textbox(left + Inches(0.25), Inches(2.0), Inches(3.25), Inches(4.4))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = ct
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = cc
        p.space_after = Pt(10)
        for line in cd.split("\n"):
            pl = tf.add_paragraph()
            pl.text = line
            pl.font.size = Pt(10)
            pl.font.color.rgb = C_WHITE if line.startswith("•") or line.startswith("Combined") else C_MUTED
            pl.space_after = Pt(3)

    # -------------------------------------------------------------
    # SLIDE 10: Milestone 5: SecRule Synthesis & Hot-Reload (Arpit)
    # -------------------------------------------------------------
    s10 = prs.slides.add_slide(blank_layout)
    set_bg(s10)
    add_header(s10, "Milestone 5: ModSecurity Rule Synthesis & Hot-Reload", "Arpit Kumar Singh (CS23I1022)")

    # Left: Rule Syntax
    c10l = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8))
    c10l.fill.solid()
    c10l.fill.fore_color.rgb = C_CARD_BG
    c10l.line.color.rgb = C_BLUE

    tb10l = s10.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.2), Inches(4.4))
    tf10l = tb10l.text_frame
    tf10l.word_wrap = True
    p = tf10l.paragraphs[0]
    p.text = "ModSecurity SecRule Synthesis"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_BLUE
    p.space_after = Pt(10)

    sec_rules_notes = [
        "Rule Directives Generated: 25 distinct SecRule definitions written to rules/wafbooster_rules.conf.",
        "Rule Template:\n  SecRule ARGS|REQUEST_URI \"@rx <pattern>\" \\\n  \"id:95000XX,phase:2,deny,status:403,\\\n   t:none,t:urlDecodeUni,msg:'...',severity:'CRITICAL'\"",
        "The URL Decoding Breakthrough: Standard ModSecurity rules missed URL-encoded payloads because params arrive as %271%27. Adding t:urlDecodeUni decodes arguments prior to regex matching.",
        "Escaping Special Quotes: Escaped internal quotes as \\x22 and \\x27 to prevent ModSecurity configuration parsing crashes."
    ]
    for n in sec_rules_notes:
        pl = tf10l.add_paragraph()
        pl.text = f"• {n}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Template" in n or "Breakthrough" in n else C_MUTED
        pl.space_after = Pt(5)

    # Right: Hot-Reload & Keep-Alive
    c10r = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.7), Inches(1.8), Inches(5.8), Inches(4.8))
    c10r.fill.solid()
    c10r.fill.fore_color.rgb = C_CARD_BG
    c10r.line.color.rgb = C_GREEN

    tb10r = s10.shapes.add_textbox(Inches(6.9), Inches(2.0), Inches(5.4), Inches(4.4))
    tf10r = tb10r.text_frame
    tf10r.word_wrap = True
    p = tf10r.paragraphs[0]
    p.text = "Zero-Downtime Hot-Reload & Keep-Alive Fix"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_GREEN
    p.space_after = Pt(10)

    reload_notes = [
        "Live Deployment Pipeline:\n  docker cp rules/wafbooster_rules.conf is-waf-1:/etc/modsecurity.d/modsecurity-override.conf",
        "Nginx Hot-Reload:\n  docker exec -u nginx is-waf-1 nginx -s reload\n(Zero container restart required, 0 packet drop).",
        "The Keep-Alive Bug Discovery: In initial testing, requests to the boosted WAF continued to bypass (reported 0/64 blocked)!",
        "Root Cause: Nginx graceful reload keeps open HTTP keep-alive connections on the OLD worker process with the OLD configuration.",
        "The Fix: Added explicit _session.close() and 1.0s sleep in Python client, forcing fresh connections to the NEW worker process. Immediately jumped to 64/64 (100%) blocked!"
    ]
    for n in reload_notes:
        pl = tf10r.add_paragraph()
        pl.text = f"• {n}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Fix" in n or "Discovery" in n else C_MUTED
        pl.space_after = Pt(5)

    # -------------------------------------------------------------
    # SLIDE 11: Milestone 6: Ablation Study (Arpit)
    # -------------------------------------------------------------
    s11 = prs.slides.add_slide(blank_layout)
    set_bg(s11)
    add_header(s11, "Milestone 6: Ablation Study — Autonomous vs. Composite Rules", "Arpit Kumar Singh (CS23I1022)")

    # Chart 2 Right embedded on Slide 11
    if os.path.exists(chart2_path):
        s11.shapes.add_picture(chart2_path, Inches(0.8), Inches(1.8), width=Inches(6.6))

    c11r = s11.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(7.7), Inches(1.8), Inches(4.8), Inches(4.8))
    c11r.fill.solid()
    c11r.fill.fore_color.rgb = C_CARD_BG
    c11r.line.color.rgb = C_BLUE

    tb11r = s11.shapes.add_textbox(Inches(7.9), Inches(2.0), Inches(4.4), Inches(4.4))
    tf11r = tb11r.text_frame
    tf11r.word_wrap = True
    p = tf11r.paragraphs[0]
    p.text = "Scientific Attribution of Coverage"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_BLUE
    p.space_after = Pt(10)

    abl_notes = [
        "Ablation Parameter: Added use_composite_patterns: bool to produce_signatures().",
        "Pure Learned Signatures (False): Relies solely on Smith-Waterman alignment and clustered subsequences. Blocked 55 / 64 (85.94%) bypassing payloads!",
        "Signatures Generated: 14 purely autonomous regexes (e.g. (?i)\\busername\\b, (?i)\\bpassword\\b, (?i)\\bSELECT\\b\\S*['\"%], (?i)\\bOR\\b\\S*['\"\\d]).",
        "What Required Composite Patterns (14.06%): The remaining 9 payloads consisted of stacked query delimiters ('; SELECT') and URL-encoded space delimiters ('%20').",
        "Key Defense Insight: Over 85% of protection is generated 100% autonomously without human domain engineering."
    ]
    for n in abl_notes:
        pl = tf11r.add_paragraph()
        pl.text = f"• {n}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Pure" in n or "Insight" in n else C_MUTED
        pl.space_after = Pt(5)

    # -------------------------------------------------------------
    # SLIDE 12: Milestone 6: Held-Out & Novel Generalization (Arpit)
    # -------------------------------------------------------------
    s12 = prs.slides.add_slide(blank_layout)
    set_bg(s12)
    add_header(s12, "Milestone 6: Out-of-Sample Generalization (+47.87% TRR)", "Arpit Kumar Singh (CS23I1022)")

    # Chart 1 embedded
    chart1_path = "/home/arpit/is/results_generalization_chart.png"
    if os.path.exists(chart1_path):
        s12.shapes.add_picture(chart1_path, Inches(0.8), Inches(1.8), width=Inches(6.4))

    # Right side: Table and findings
    c12r = s12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(7.5), Inches(1.8), Inches(5.0), Inches(4.8))
    c12r.fill.solid()
    c12r.fill.fore_color.rgb = C_CARD_BG
    c12r.line.color.rgb = C_GREEN

    tb12r = s12.shapes.add_textbox(Inches(7.7), Inches(2.0), Inches(4.6), Inches(4.4))
    tf12r = tb12r.text_frame
    tf12r.word_wrap = True
    p = tf12r.paragraphs[0]
    p.text = "Empirical Held-Out Findings"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_GREEN
    p.space_after = Pt(10)

    gen_notes = [
        "Avoiding Circular Evaluation: Signatures were never trained on test.csv or novel_generated.",
        "Held-Out Malicious (test.csv, 93 samples):\n  Baseline: 97.85% (91/93)\n  Boosted:  100.00% (93/93) [+2.15%]",
        "Held-Out Benign (test.csv, 300 samples):\n  Baseline: 100.00% (300/300)\n  Boosted:  100.00% (300/300) [0% FRR]",
        "Novel Unseen GRU Attacks (94 samples):\n  Baseline: 51.06% (48/94) -> CRS collapses!\n  Boosted:  98.94% (93/94) [+47.87% 🔥]",
        "Conclusion: WAFBooster repairs blind spots for entire mutant distributions, not just memorized payloads."
    ]
    for n in gen_notes:
        pl = tf12r.add_paragraph()
        pl.text = f"• {n}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Novel" in n or "Conclusion" in n else C_MUTED
        pl.space_after = Pt(5)

    # -------------------------------------------------------------
    # SLIDE 13: Milestone 6: Failure Analysis (Arpit)
    # -------------------------------------------------------------
    s13 = prs.slides.add_slide(blank_layout)
    set_bg(s13)
    add_header(s13, "Milestone 6: Deep Dive into the 1 Bypassing Attack Mutant", "Arpit Kumar Singh (CS23I1022)")

    # Left: The Payload and Analysis
    c13l = s13.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.8))
    c13l.fill.solid()
    c13l.fill.fore_color.rgb = C_CARD_BG
    c13l.line.color.rgb = C_RED

    tb13l = s13.shapes.add_textbox(Inches(1.0), Inches(2.0), Inches(5.2), Inches(4.4))
    tf13l = tb13l.text_frame
    tf13l.word_wrap = True
    p = tf13l.paragraphs[0]
    p.text = "The Single Bypassing Mutant"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_RED
    p.space_after = Pt(10)

    fail_points = [
        "Out of 94 novel GRU mutants, exactly 1 payload bypassed both Baseline and Boosted WAF:\n\n  '<UNK> OR 2 > 1'",
        "Root Cause 1: \\S* Non-Whitespace Wildcard\n  Rule 1 uses (?i)\\bOR\\b\\S*['\"\\d]. Because the payload contained a space ('OR 2'), the \\S* qualifier could not bridge across whitespace.",
        "Root Cause 2: Relational Operator Substitution\n  Rule 14 matches numeric comparisons ['\"\\d]\\s*=\\s*['\"\\d] (e.g. 1=1). The mutant replaced '=' with '>', evading equality checks.",
        "Root Cause 3: Out-of-Vocabulary Prefix\n  '<UNK>' appeared because the GRU sampled an unknown token tokenized as a literal string."
    ]
    for pt in fail_points:
        pl = tf13l.add_paragraph()
        pl.text = f"• {pt}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Root" in pt else C_MUTED
        pl.space_after = Pt(5)

    # Right: The 2 Held-Out Malicious Bypasses Caught
    c13r = s13.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.7), Inches(1.8), Inches(5.8), Inches(4.8))
    c13r.fill.solid()
    c13r.fill.fore_color.rgb = C_CARD_BG
    c13r.line.color.rgb = C_GREEN

    tb13r = s13.shapes.add_textbox(Inches(6.9), Inches(2.0), Inches(5.4), Inches(4.4))
    tf13r = tb13r.text_frame
    tf13r.word_wrap = True
    p = tf13r.paragraphs[0]
    p.text = "The 2 Held-Out Payloads Caught by Boosted WAF"
    p.font.size = Pt(14)
    p.font.bold = True
    p.font.color.rgb = C_GREEN
    p.space_after = Pt(10)

    caught_points = [
        "In test.csv, exactly 2 malicious payloads bypassed Baseline CRS (waf_label = 0) but were stopped by Boosted WAF:\n",
        "Payload 1 (Row 40):\n  '1; SelEcT * FrOM useRS'\n  -> Stopped by Rule 4: ;\\s*(?i:SELECT|INSERT...)\\b\n  -> Stopped by Rule 17: (?i)\\busERs\\b",
        "Payload 2 (Row 317):\n  '1;%20SELECT%20*%20FROM%20users'\n  -> Stopped by Rule 11: (?i)%20(?:SELECT|UNION)%20",
        "Why Baseline Failed: CRS Paranoia Level 1 assigns low anomaly score to stacked queries without comments or quotes. WAFBooster closed this vulnerability."
    ]
    for pt in caught_points:
        pl = tf13r.add_paragraph()
        pl.text = f"• {pt}"
        pl.font.size = Pt(10)
        pl.font.color.rgb = C_WHITE if "Payload" in pt else C_MUTED
        pl.space_after = Pt(5)

    # -------------------------------------------------------------
    # SLIDE 14: Threats to Validity & Conclusion (Arpit)
    # -------------------------------------------------------------
    s14 = prs.slides.add_slide(blank_layout)
    set_bg(s14)
    add_header(s14, "Threats to Validity, Production Impact & Conclusion", "Arpit Kumar Singh (CS23I1022)")

    cards_14 = [
        ("Threats to Validity",
         "Honest scientific appraisal of experimental constraints:\n\n"
         "• Seed-Family Leakage:\n  Mutants derived from 30 seed families may share structural roots across splits. (Mitigated by novel GRU seeds).\n"
         "• Synthetic vs. Real Traffic:\n  CSIC 2010 represents e-commerce traffic; modern REST/JSON APIs may introduce novel token distributions.\n"
         "• Single Qualifier Limitation:\n  Paper's restriction to \\S* wildcards prevents matching across arbitrary whitespace.",
         C_RED),
        ("Production Recommendations",
         "Architectural enhancements for enterprise deployment:\n\n"
         "• Shadow Canary Deployment:\n  Deploy generated rules in 'DetectionOnly' mode for 48 hours to audit live false positives.\n"
         "• Whitespace Generalization:\n  Replace strict \\S* with [\\s\\S]*? or add t:compressWhitespace transformations.\n"
         "• Multi-Stage Retraining:\n  Continuously retrain ShadowCNN as attackers discover new mutation operators.",
         C_BLUE),
        ("Project Summary",
         "Full realization of IEEE TDSC 2025 WAFBooster:\n\n"
         "• Built end-to-end local Docker testbed with live OWASP ModSecurity CRS.\n"
         "• Retuned ShadowCNN: 96.69% test accuracy.\n"
         "• Repaired Algorithm 1 semantic destruction bug.\n"
         "• Boosted novel attack TRR by +47.87% (51.06% -> 98.94%) with strictly 0.00% False Rejection Rate.",
         C_GREEN),
    ]
    for i, (ct, cd, cc) in enumerate(cards_14):
        left = Inches(0.8 + i * 3.95)
        card = s14.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.8), Inches(3.75), Inches(4.8))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD_BG
        card.line.color.rgb = cc
        card.line.width = Pt(1.5)

        tb = s14.shapes.add_textbox(left + Inches(0.25), Inches(2.0), Inches(3.25), Inches(4.4))
        tf = tb.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = ct
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = cc
        p.space_after = Pt(10)
        for line in cd.split("\n"):
            pl = tf.add_paragraph()
            pl.text = line
            pl.font.size = Pt(10)
            pl.font.color.rgb = C_WHITE if line.startswith("•") else C_MUTED
            pl.space_after = Pt(3)

    # Save
    out_path = "/home/arpit/is/WAFBooster_14_Slide_Presentation.pptx"
    prs.save(out_path)
    print(f"Saved 14-slide presentation to: {out_path}")

if __name__ == "__main__":
    create_14_slide_deck()

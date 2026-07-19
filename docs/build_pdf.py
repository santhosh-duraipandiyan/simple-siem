"""Build the 'Understanding SIEM' explainer PDF."""
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Image,
                                Table, TableStyle, Preformatted, PageBreak,
                                HRFlowable, ListFlowable, ListItem)

OUT = "Understanding-SIEM.pdf"
DIAGRAM = "architecture.png"

# ---------- palette ----------
INK = colors.HexColor("#1f2937")
MUTED = colors.HexColor("#6b7280")
ACCENT = colors.HexColor("#7f1d1d")
CYAN = colors.HexColor("#0891b2")
GREEN = colors.HexColor("#16a34a")
AMBER = colors.HexColor("#b45309")
PURPLE = colors.HexColor("#7e22ce")
CODE_BG = colors.HexColor("#f3f4f6")
CODE_BORDER = colors.HexColor("#d1d5db")

styles = getSampleStyleSheet()

def S(name, **kw):
    styles.add(ParagraphStyle(name, parent=styles["Normal"], **kw))

S("CoverTitle", fontName="Helvetica-Bold", fontSize=30, leading=36,
  textColor=INK, alignment=TA_CENTER)
S("CoverSub", fontName="Helvetica", fontSize=14, leading=20,
  textColor=MUTED, alignment=TA_CENTER)
S("H1", fontName="Helvetica-Bold", fontSize=17, leading=22, textColor=ACCENT,
  spaceBefore=16, spaceAfter=8)
S("H2", fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=INK,
  spaceBefore=10, spaceAfter=5)
S("Body", fontName="Helvetica", fontSize=10.5, leading=15.5, textColor=INK,
  spaceAfter=7, alignment=TA_LEFT)
S("Bull", fontName="Helvetica", fontSize=10.5, leading=15, textColor=INK)
S("Caption", fontName="Helvetica-Oblique", fontSize=9, leading=12,
  textColor=MUTED, alignment=TA_CENTER, spaceBefore=4)
S("CodeSty", fontName="Courier", fontSize=8.7, leading=11.5,
  textColor=colors.HexColor("#111827"))

story = []


def para(text, style="Body"):
    story.append(Paragraph(text, styles[style]))


def h1(t): story.append(Paragraph(t, styles["H1"]))
def h2(t): story.append(Paragraph(t, styles["H2"]))
def sp(h=6): story.append(Spacer(1, h))


def bullets(items):
    lf = ListFlowable(
        [ListItem(Paragraph(t, styles["Bull"]), leftIndent=6, value="•")
         for t in items],
        bulletType="bullet", leftIndent=14, bulletColor=ACCENT)
    story.append(lf)
    sp(6)


def code(text):
    tbl = Table([[Preformatted(text, styles["CodeSty"])]], colWidths=[6.7 * inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, CODE_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(tbl)
    sp(8)


# ======================= COVER =======================
sp(70)
para("Understanding SIEM", "CoverTitle")
sp(8)
para("A hands-on guide built around a simple, console-based, "
     "Docker-powered SIEM you can run yourself", "CoverSub")
sp(26)
story.append(HRFlowable(width="55%", thickness=1.2, color=CODE_BORDER,
                        spaceBefore=4, spaceAfter=4, hAlign="CENTER"))
sp(16)
story.append(Image(DIAGRAM, width=6.7 * inch, height=6.7 * inch * (1350 / 2370)))
para("Figure 1 — End-to-end architecture and data flow of the Simple SIEM.",
     "Caption")
story.append(PageBreak())

# ======================= 1. WHAT IS SIEM =======================
h1("1. What is a SIEM?")
para("A <b>SIEM</b> — Security Information and Event Management — is the system "
     "a security team uses to watch everything happening across a network in one "
     "place. Every server, firewall, router, application, and cloud service "
     "constantly produces <i>logs</i>: small text records of who did what and "
     "when. On their own these logs are scattered across hundreds of machines, "
     "written in dozens of incompatible formats, and far too numerous for anyone "
     "to read. A SIEM exists to solve that problem.")
para("At its core, a SIEM does three things, and this project is organised around "
     "exactly those three stages:")
bullets([
    "<b>Collection</b> — gather logs from every source into one pipeline.",
    "<b>Normalization</b> — translate every log format into one common structure "
    "so they can be compared.",
    "<b>Correlation &amp; Alerting</b> — analyse many events together to detect "
    "attacks, and raise an alert when something looks malicious.",
])
para("A real SIEM (Splunk, Elastic Security, Microsoft Sentinel, Wazuh, and "
     "others) adds storage, search, dashboards, and long-term retention on top. "
     "But the three stages above are the beating heart of every one of them. "
     "Understanding them is the goal of this project.")

h2("Why not just read the logs directly?")
para("Imagine a single failed SSH login on one server. Harmless — people mistype "
     "passwords. Now imagine ten failed logins from the same foreign IP address in "
     "thirty seconds, immediately followed by a success. That is almost certainly "
     "an attacker who just guessed a password. No human is watching every server "
     "at 3 a.m., and the meaningful signal is spread across many individual log "
     "lines. A SIEM connects those dots automatically. That connecting-the-dots is "
     "called <i>correlation</i>, and it is the reason SIEMs exist.")

# ======================= 2. THE THREE STAGES =======================
h1("2. The three stages, and how this system demonstrates each one")

h2("Stage 1 — Collection")
para("<b>The concept:</b> pull raw logs in from every source and get them into a "
     "single pipeline, without yet trying to understand their contents. This is "
     "the SIEM's front door.")
para("<b>In this system:</b> the <font name=Courier>collector</font> container "
     "reads every raw log off a queue and wraps each one in a common 'envelope' — "
     "a unique <font name=Courier>event_id</font>, the time it was received, and "
     "which source it came from — then passes it on. It deliberately does not parse "
     "the message yet, which keeps the stage simple and its single job obvious.")

h2("Stage 2 — Normalization")
para("<b>The concept:</b> different devices describe the same kind of event in "
     "completely different text. Normalization rewrites all of them into one shared "
     "schema, so that an SSH log, a firewall log, and a web-server log can be "
     "counted and compared using the same fields. This is the single most "
     "important idea in a SIEM.")
para("<b>In this system:</b> the <font name=Courier>normalizer</font> container "
     "applies one regular expression per source format and produces a uniform JSON "
     "event with fields such as <font name=Courier>category</font>, "
     "<font name=Courier>action</font>, <font name=Courier>outcome</font>, "
     "<font name=Courier>src_ip</font>, <font name=Courier>user</font>, "
     "<font name=Courier>dst_port</font>, and <font name=Courier>path</font>. "
     "Three unrecognisable raw lines become three events with identical shape:")
code(
 'RAW  (auth)     Jul 18 10:22:01 web01 sshd[4521]: Failed password for\n'
 '                root from 203.0.113.45 port 52344 ssh2\n'
 'RAW  (firewall) FW: DENY TCP 198.51.100.23:44123 -> 10.0.0.5:3389 len=52\n'
 'RAW  (web)      192.0.2.10 - - [.../...] "GET /admin.php HTTP/1.1" 404 ...\n'
 '                          |\n'
 '                          v   after normalization\n'
 '{ "category": "authentication", "action": "ssh_login",\n'
 '  "outcome": "failure", "src_ip": "203.0.113.45", "user": "root" }')

h2("Stage 3 — Correlation &amp; Alerting")
para("<b>The concept:</b> examine many normalized events over a window of time and "
     "decide when a <i>pattern</i> is an attack. One event rarely matters; the "
     "relationship between events does.")
para("<b>In this system:</b> the <font name=Courier>correlator</font> container "
     "keeps a short, per-IP sliding-window history in memory and runs a small set "
     "of detection rules on every event. When a rule's threshold is crossed it "
     "prints a clearly formatted, colour-coded alert box to the console. The "
     "built-in rules are:")

rule_data = [
    ["Rule", "Fires when", "Severity"],
    ["SSH brute force", "≥ 5 failed SSH logins from one IP within 30s", "HIGH"],
    ["Brute-force success", "a successful login right after those failures", "CRITICAL"],
    ["Port scan", "one IP blocked on ≥ 10 different ports within 30s", "MEDIUM"],
    ["Web application scan", "≥ 4 suspicious web requests (sqlmap, /admin, ../, SQLi)", "HIGH"],
]
t = Table(rule_data, colWidths=[1.5 * inch, 3.9 * inch, 1.3 * inch])
t.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
    ("FONTSIZE", (0, 0), (-1, -1), 9.5),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#faf5f5")]),
    ("GRID", (0, 0), (-1, -1), 0.5, CODE_BORDER),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("TOPPADDING", (0, 0), (-1, -1), 6),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ("LEFTPADDING", (0, 0), (-1, -1), 8),
]))
story.append(t)
sp(6)
para("All thresholds are plain constants at the top of "
     "<font name=Courier>correlator.py</font> — students can change them, re-run, "
     "and watch how detection sensitivity (and false positives) change.")

# ======================= 3. HOW IT IS BUILT =======================
h1("3. How the system is built")
para("The whole thing runs as five Docker containers started with a single "
     "command. Four of them are short Python programs that share one Docker image; "
     "the fifth is Redis, which acts as the conveyor belt between stages.")
bullets([
    "<b>generator</b> — simulates the network's devices. It emits fake auth, "
    "firewall, and web logs as background 'noise', and every so often launches a "
    "scripted attack so alerts reliably appear.",
    "<b>collector</b> — Stage 1 (collection).",
    "<b>normalizer</b> — Stage 2 (normalization).",
    "<b>correlator</b> — Stage 3 (correlation &amp; alerting).",
    "<b>redis</b> — an in-memory data store used here as simple FIFO queues that "
    "connect the stages.",
])
para("The stages never call each other directly. Each one only reads from its "
     "input queue and writes to the next, using two Redis operations:")
code(
 'while True:\n'
 '    msg = pop(from_my_input_queue)     # BRPOP: sleep until work arrives\n'
 '    result = do_my_job(msg)            # collect / normalize / correlate\n'
 '    push(to_the_next_queue, result)    # LPUSH: hand off to the next stage')
para("The three queues carry data along the pipeline:")
code(
 'generator  --[ raw_logs  ]-->  collector\n'
 'collector  --[ collected ]-->  normalizer\n'
 'normalizer --[ events    ]-->  correlator  --> ALERTS on your screen')
para("Because the stages are decoupled through queues, each is an independent "
     "container that could be scaled, restarted, or replaced on its own. This is "
     "exactly how production SIEM pipelines separate ingestion, parsing, and "
     "detection — just with heavier tools (Kafka, Logstash, and so on) in place of "
     "Redis and Python.")

# ======================= 4. HOW TO USE =======================
h1("4. How to run and use it")
h2("Prerequisites")
para("You only need <b>Docker Desktop</b> (or Docker Engine with the Compose "
     "plugin) installed. No Python setup is required on your machine — everything "
     "runs inside the containers.")

h2("Start everything with one command")
code("cd simple-siem\n"
     "docker compose up --build")
para("Docker builds one small image, then starts all five containers. Within a "
     "minute or two you will see colour-coded logs from every stage interleaved in "
     "your terminal, and the correlator will begin printing red alert boxes when "
     "the generator launches an attack.")

h2("Focus on a single stage")
para("The combined stream is busy on purpose — it shows the whole pipeline at "
     "once. To watch just one stage, open a second terminal and follow that "
     "container's logs:")
code("docker compose logs -f correlator      # just the alerts\n"
     "docker compose logs -f normalizer      # watch raw logs become JSON\n"
     "docker compose logs -f generator       # see the simulated attacks start")

h2("Stop and clean up")
code("# press Ctrl+C in the terminal running compose, then:\n"
     "docker compose down")

h2("What a firing alert looks like")
para("When a rule trips, the correlator prints a block like this:")
code(
 '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n'
 '  ALERT #1  [HIGH]  SSH BRUTE FORCE\n'
 '  attacker : 203.0.113.45\n'
 '  what     : 5 failed SSH logins in 30s\n'
 '  evidence : target user=\'root\'\n'
 '  time     : 2026-07-18 10:22:03\n'
 '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
para("Read it top to bottom: the severity and rule name tell you <i>what</i> was "
     "detected, the attacker line tells you <i>who</i>, and the evidence line "
     "tells you <i>why</i> the SIEM believes it is an attack.")

# ======================= 5. EXTEND =======================
h1("5. Ideas for students to extend it")
bullets([
    "Add a brand-new log source (DNS or VPN logs): write a format in the "
    "generator, a matching regex in the normalizer, and a rule in the correlator.",
    "Add a rule that alerts when the same user logs in from two different "
    "countries in a short window (impossible travel).",
    "Write alerts to a file or a dedicated Redis queue instead of the screen, then "
    "build a tiny dashboard that reads them.",
    "Lower the thresholds and watch false positives appear — the real tuning "
    "problem every security operations centre faces.",
])
sp(8)
story.append(HRFlowable(width="100%", thickness=0.75, color=CODE_BORDER,
                        spaceBefore=6, spaceAfter=8))
para("<i>This is a learning tool, not a production security product. All logs are "
     "synthetic and the detection logic is intentionally simplified so that the "
     "core ideas stay visible.</i>", "Caption")


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(0.9 * inch, 0.55 * inch, "Understanding SIEM · Simple SIEM teaching build")
    canvas.drawRightString(7.6 * inch, 0.55 * inch, "Page %d" % doc.page)
    canvas.restoreState()


doc = SimpleDocTemplate(OUT, pagesize=LETTER,
                        leftMargin=0.9 * inch, rightMargin=0.9 * inch,
                        topMargin=0.85 * inch, bottomMargin=0.85 * inch,
                        title="Understanding SIEM",
                        author="Simple SIEM teaching build")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print("wrote", OUT)

"""
app.py  –  PhishGuard AI
========================
A beginner-friendly phishing email detection dashboard built with Streamlit.

How to run
----------
1. Install dependencies (once):
       pip install streamlit plotly

2. Start the app:
       streamlit run app.py

   Streamlit will print a local URL (usually http://localhost:8501) and
   open it in your browser automatically.

How it works
------------
When you paste an email and click "Analyze Email", the app runs the text
through a set of plain-Python rules defined in the RULES list below.
Each rule looks for a specific phishing pattern (urgency language,
credential requests, suspicious URLs, etc.) and adds a fixed number of
points to a risk score.  The final score (0–100) determines the risk level:

  • 0–39   → Low Risk    (probably safe)
  • 40–69  → Medium Risk (worth investigating)
  • 70–100 → High Risk   (strong phishing indicators)

No network requests are made.  No links are opened.  No files are executed.
Everything is read-only text analysis.
"""

import re                          # built-in: search text with patterns
import streamlit as st             # web UI framework
import plotly.graph_objects as go  # interactive charts


# =============================================================================
# DETECTION ENGINE  (rules + scoring)
# =============================================================================

# ── Rule definitions ──────────────────────────────────────────────────────────
# Each rule is a dictionary with four keys:
#   name        – short label shown in the UI
#   explanation – plain-English description of why this pattern is suspicious
#   points      – how many risk points this rule contributes
#   check       – a function(subject, body) → True if the pattern is found
#
# Lambda functions are used here because each check is just one expression.
# A lambda is an anonymous (unnamed) function: lambda arg1, arg2: expression

RULES = [

    # ── 1. Urgency / pressure language ────────────────────────────────────────
    # Phishing emails pressure recipients to act without thinking.
    # Words like "urgent", "immediately", "final notice" are common triggers.
    # Legitimate emails can also use urgency, so this rule alone is modest.
    {
        "name": "Urgency / pressure language",
        "explanation": (
            "The email uses words designed to make you act quickly without thinking — "
            "a common tactic in phishing. Examples: 'urgent', 'immediately', "
            "'within 24 hours', 'act now', 'final notice'."
        ),
        "points": 15,
        "check": lambda subj, body: bool(re.search(
            r"\b(urgent|immediately|act now|final notice|last chance|"
            r"within \d+ hours?|expires? (today|soon)|do not (ignore|delay)|"
            r"respond (now|immediately|today))\b",
            (subj + " " + body).lower()
        )),
    },

    # ── 2. Account suspension threat ──────────────────────────────────────────
    # Threatening to lock or close your account is a classic scare tactic.
    {
        "name": "Account suspension threat",
        "explanation": (
            "The email threatens to suspend, close, or lock your account if you "
            "don't act. Legitimate companies almost never send threats like this "
            "without multiple prior warnings through official channels."
        ),
        "points": 20,
        "check": lambda subj, body: bool(re.search(
            r"\b(account (will be|has been) (suspended|closed|terminated|locked|deactivated)|"
            r"permanently (suspend|close|terminate|block)|"
            r"lose (access|your account)|account (closure|termination))\b",
            (subj + " " + body).lower()
        )),
    },

    # ── 3. Sensitive credential request ───────────────────────────────────────
    # No legitimate company will ever ask for your password, OTP, PIN, SSN,
    # or full card details by email.
    {
        "name": "Requests sensitive credentials",
        "explanation": (
            "The email asks for passwords, OTPs, PINs, Social Security Numbers, "
            "or bank details. No legitimate company will ever ask for this "
            "information by email."
        ),
        "points": 30,
        "check": lambda subj, body: bool(re.search(
            r"\b(password|passcode|otp|one.time (password|code|pin)|"
            r"social security( number)?|ssn|bank (account|routing)|"
            r"credit card (number|details)|cvv|"
            r"confirm your (identity|details|credentials)|"
            r"provide your (password|pin|ssn|card))\b",
            (subj + " " + body).lower()
        )),
    },

    # ── 4. Suspicious URL pattern ─────────────────────────────────────────────
    # Phishing URLs often use HTTP (unencrypted), IP addresses, hyphens that
    # mimic real brands, random tokens, or unusual domain extensions.
    # We only read the URL text — we never visit the link.
    {
        "name": "Suspicious URL pattern",
        "explanation": (
            "A link in the email shows warning signs: it may use HTTP instead of "
            "HTTPS, contain an IP address, use hyphens to mimic a trusted brand, "
            "have a long random token, or use an unusual domain extension "
            "(.xyz, .info, .biz, .net used unexpectedly)."
        ),
        "points": 25,
        "check": lambda subj, body: bool(re.search(
            r"(http://[^\s]+|"
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"https?://[^\s]*-[^\s]*\.(net|org|info|biz|xyz|co|io)/|"
            r"\?[^\s]{0,10}token=[a-zA-Z0-9]{6,}|"
            r"https?://[^\s]+\.(xyz|info|biz|click|tk|ml|ga|cf)\b)",
            (subj + " " + body).lower()
        )),
    },

    # ── 4b. Unsolicited offer with unencrypted link ───────────────────────────
    # A marketing-style message combined with an HTTP link is a "grey mail"
    # pattern — not definitively malicious, but worth flagging as suspicious.
    {
        "name": "Unsolicited offer with unencrypted link",
        "explanation": (
            "The email contains an HTTP (unencrypted) link alongside marketing "
            "language like 'exclusive offer', 'limited time', or 'selected for you'. "
            "Unsolicited commercial emails with unencrypted links are a common "
            "vector for data harvesting."
        ),
        "points": 20,
        "check": lambda subj, body: bool(
            re.search(r"http://[^\s]+", (subj + " " + body).lower()) and
            re.search(
                r"\b(exclusive (offer|deal|discount)|limited.time|"
                r"selected for you|personally selected|"
                r"members.only|special (offer|deal|discount))\b",
                (subj + " " + body).lower()
            )
        ),
    },

    # ── 5. Prize / reward / lottery claim ────────────────────────────────────
    # "You've won!" messages are almost exclusively scam emails.
    {
        "name": "Prize or reward claim",
        "explanation": (
            "The email claims you have won a prize, lottery, or reward that you "
            "never entered. This is a well-known social-engineering trick used to "
            "get you to hand over personal or payment details."
        ),
        "points": 25,
        "check": lambda subj, body: bool(re.search(
            r"\b(you('ve| have) won|congratulations.{0,30}(won|winner|selected)|"
            r"claim your (prize|reward|gift card|voucher)|"
            r"lucky (winner|draw|selection)|"
            r"selected (as|for) (today'?s?|our) (winner|prize|reward))\b",
            (subj + " " + body).lower()
        )),
    },

    # ── 6. Click-to-verify or update request ─────────────────────────────────
    # Asking you to click a link to "verify" or "update billing" drives victims
    # to fake login pages designed to steal credentials.
    {
        "name": "Click-to-verify or update request",
        "explanation": (
            "The email asks you to click a link to verify your identity, confirm "
            "your details, or update your payment information. Phishing emails "
            "use this pattern to direct victims to fake login pages."
        ),
        "points": 15,
        "check": lambda subj, body: bool(re.search(
            r"\b(click (here|the link|below) to (verify|confirm|update|restore|"
            r"secure|recover|reset)|"
            r"update your (billing|payment|card|bank|account) (information|details)|"
            r"confirm your (email|account|identity|details))\b",
            (subj + " " + body).lower()
        )),
    },

    # ── 7. Unexpected attachment mentioned ───────────────────────────────────
    # Malicious attachments (fake invoices, documents) are a common malware
    # delivery method.  We check for the language, not an actual file.
    {
        "name": "Unexpected attachment mentioned",
        "explanation": (
            "The email mentions an attachment (invoice, document, receipt) that "
            "you were not expecting. Malicious attachments are a common way "
            "attackers deliver malware. Never open unexpected attachments."
        ),
        "points": 15,
        "check": lambda subj, body: bool(re.search(
            r"\b(open (the |this )?(attached|attachment)|"
            r"(attached|attachment).{0,30}(invoice|document|receipt|file|pdf|zip|"
            r"doc|docx|xls|xlsx)|"
            r"download (the |this )?(attached|attachment|file)|"
            r"see (the |this )?attached)\b",
            (subj + " " + body).lower()
        )),
    },

    # ── 8. Possible brand impersonation ──────────────────────────────────────
    # If an email mentions a well-known brand but contains no link to that
    # brand's real domain, it may be impersonating that brand.
    {
        "name": "Possible brand impersonation",
        "explanation": (
            "The email mentions a well-known brand (PayPal, Microsoft, Amazon, "
            "etc.) but does not appear to come from that brand's official domain. "
            "Attackers impersonate trusted companies to lower your guard."
        ),
        "points": 20,
        "check": lambda subj, body: _check_brand_impersonation(subj, body),
    },
]


def _check_brand_impersonation(subject: str, body: str) -> bool:
    """
    Return True when a known brand is mentioned in the email but no link
    to that brand's official domain appears in the text.

    Example:
      Text says "PayPal" but links to 'paypa1-helpdesk.org'  → True  (suspicious)
      Text says "PayPal" and links to 'paypal.com'            → False (looks fine)
    """
    # brand name  →  acceptable official domain fragments
    BRANDS = {
        "paypal":    ["paypal.com"],
        "microsoft": ["microsoft.com", "microsoftonline.com", "live.com"],
        "amazon":    ["amazon.com", "amazon.co.uk", "amazonaws.com"],
        "netflix":   ["netflix.com"],
        "apple":     ["apple.com", "icloud.com"],
        "google":    ["google.com", "gmail.com", "googlemail.com"],
        "facebook":  ["facebook.com", "fb.com"],
        "instagram": ["instagram.com"],
        "twitter":   ["twitter.com", "x.com"],
        "irs":       ["irs.gov"],
        "github":    ["github.com"],
        "dropbox":   ["dropbox.com"],
    }

    combined = (subject + " " + body).lower()

    for brand, official_domains in BRANDS.items():
        if brand in combined:
            # Brand is mentioned — check whether an official domain is also present
            found_official = any(domain in combined for domain in official_domains)
            if not found_official:
                return True   # Brand mentioned but no official domain → suspicious

    return False


def analyse_email(subject: str, body: str) -> dict:
    """
    Analyse a single email and return a results dictionary.

    Parameters
    ----------
    subject : str   The email subject line.
    body    : str   The full email body text.

    Returns
    -------
    dict with keys:
        score        – int, 0–100
        level        – "Low Risk" | "Medium Risk" | "High Risk"
        level_class  – CSS helper class name for colour coding in the UI
        indicators   – list of matched-rule dicts (name, explanation, points)
    """
    total_points = 0   # running total before the 100-point cap
    indicators   = []  # rules that matched

    for rule in RULES:
        if rule["check"](subject, body):      # run this rule's check function
            total_points += rule["points"]
            indicators.append({
                "name":        rule["name"],
                "explanation": rule["explanation"],
                "points":      rule["points"],
            })

    score = min(total_points, 100)  # cap at 100

    if score >= 70:
        level, level_class = "High Risk",   "risk-high"
    elif score >= 40:
        level, level_class = "Medium Risk", "risk-medium"
    else:
        level, level_class = "Low Risk",    "risk-low"

    return {
        "score":       score,
        "level":       level,
        "level_class": level_class,
        "indicators":  indicators,
    }


# =============================================================================
# SAMPLE EMAIL DATASET  (fictional data for testing)
# =============================================================================

SAMPLE_EMAILS = [
    # ── Phishing (10) ─────────────────────────────────────────────────────────
    {
        "Subject": "URGENT: Verify your bank account immediately",
        "Sender":  "security-alert@fakebank-secure.net",
        "Body": (
            "Dear valued customer, your account has been flagged for unusual activity. "
            "You must verify your details within 24 hours or your account will be permanently suspended. "
            "Click here: http://fakebank-secure.net/verify?token=abc123"
        ),
        "Category":    "Phishing",
        "Explanation": "Impersonates a bank, creates false urgency, contains a suspicious verification link.",
    },
    {
        "Subject": "You've won a $1,000 Amazon gift card!",
        "Sender":  "prizes@amazn-rewards-claim.com",
        "Body": (
            "Congratulations! You have been selected as today's lucky winner. "
            "Claim your $1,000 Amazon gift card now before it expires. "
            "Enter your shipping address and credit card details at: http://amazn-rewards-claim.com/claim"
        ),
        "Category":    "Phishing",
        "Explanation": "Classic prize scam requesting credit card information via a lookalike domain.",
    },
    {
        "Subject": "Your PayPal account is limited — action required",
        "Sender":  "support@paypa1-helpdesk.org",
        "Body": (
            "We have noticed suspicious login attempts on your PayPal account. "
            "To restore full access, please confirm your identity by providing your password and SSN. "
            "Failure to act within 48 hours will result in permanent closure."
        ),
        "Category":    "Phishing",
        "Explanation": "Typosquatted sender domain ('paypa1'), requests password and SSN, uses fear tactics.",
    },
    {
        "Subject": "IT Department: Reset your password NOW",
        "Sender":  "it-helpdesk@corp-internal-support.xyz",
        "Body": (
            "Hi employee, our system detected that your corporate password has expired. "
            "Please log in immediately using the link below and create a new password. "
            "Link: http://corp-internal-support.xyz/reset"
        ),
        "Category":    "Phishing",
        "Explanation": "Spoofs an internal IT department. External domain used for credential harvesting.",
    },
    {
        "Subject": "Final notice: Your Netflix subscription has been cancelled",
        "Sender":  "billing@netf1ix-accounts.com",
        "Body": (
            "Your Netflix payment method has been declined. "
            "To avoid losing access, update your billing information immediately: "
            "http://netf1ix-accounts.com/update-billing"
        ),
        "Category":    "Phishing",
        "Explanation": "Lookalike domain ('netf1ix'), harvests payment details under threat of service loss.",
    },
    {
        "Subject": "Security Alert: Your email password was changed",
        "Sender":  "no-reply@mail-security-alert.info",
        "Body": (
            "Someone changed your email password from an unknown device. "
            "If this was not you, click the link below to recover your account immediately. "
            "Recovery link: http://mail-security-alert.info/recover?id=9921"
        ),
        "Category":    "Phishing",
        "Explanation": "Creates panic about account takeover and directs to a credential-harvesting page.",
    },
    {
        "Subject": "You have a pending package — confirm your address",
        "Sender":  "delivery@dh1-parcel-track.com",
        "Body": (
            "A parcel is waiting for you. We were unable to deliver it due to an address mismatch. "
            "Pay a small re-delivery fee of $1.99 to confirm your address: "
            "http://dh1-parcel-track.com/redeliver"
        ),
        "Category":    "Phishing",
        "Explanation": "Parcel scam requesting payment card details for a fabricated delivery fee.",
    },
    {
        "Subject": "IRS Tax Refund: Claim your $3,240 refund",
        "Sender":  "refunds@irs-tax-refund-portal.net",
        "Body": (
            "Our records show you are eligible for a federal tax refund of $3,240.00. "
            "To process your refund, submit your Social Security Number and bank routing number at: "
            "http://irs-tax-refund-portal.net/claim"
        ),
        "Category":    "Phishing",
        "Explanation": "Impersonates the IRS to steal SSN and bank details. Real IRS never emails refund links.",
    },
    {
        "Subject": "Your Microsoft 365 licence expires today",
        "Sender":  "licencing@micros0ft-365-renew.com",
        "Body": (
            "Your Microsoft 365 subscription expires today. "
            "Renew now to avoid losing access to your emails and files. "
            "Click to renew: http://micros0ft-365-renew.com/renew?user=you"
        ),
        "Category":    "Phishing",
        "Explanation": "Typosquatted Microsoft domain ('micros0ft'), harvests payment details under urgency.",
    },
    {
        "Subject": "HR: Important — update your direct deposit information",
        "Sender":  "hr-payroll@yourcompany-hrportal.net",
        "Body": (
            "Dear team member, our payroll system is being upgraded. "
            "All employees must update their direct deposit information before Friday "
            "to ensure uninterrupted salary payments. Update here: http://yourcompany-hrportal.net/dd"
        ),
        "Category":    "Phishing",
        "Explanation": "Business email compromise (BEC) attack targeting banking credentials via a fake HR portal.",
    },
    # ── Suspicious (5) ────────────────────────────────────────────────────────
    {
        "Subject": "Special offer — limited time discount for you",
        "Sender":  "deals@shopmail-promos.co",
        "Body": (
            "Hi there! We have an exclusive offer just for you. "
            "Click the link to see today's discount: http://shopmail-promos.co/deals?ref=user99. "
            "Unsubscribe at any time."
        ),
        "Category":    "Suspicious",
        "Explanation": "Unsolicited marketing from an unknown domain with a tracking link. Warrants caution.",
    },
    {
        "Subject": "Your account login from a new location",
        "Sender":  "notifications@socialapp-noreply.io",
        "Body": (
            "We noticed a login to your account from a new device in a different city. "
            "If this was you, no action is needed. If not, secure your account at: "
            "http://socialapp-noreply.io/secure"
        ),
        "Category":    "Suspicious",
        "Explanation": "Could be legitimate but the generic sender domain and non-branded URL are red flags.",
    },
    {
        "Subject": "Invitation: Join our exclusive investment community",
        "Sender":  "invest@wealthclub-private.org",
        "Body": (
            "You have been personally selected to join our members-only investment group. "
            "Our members average 40% monthly returns. "
            "Register your free spot today: http://wealthclub-private.org/join"
        ),
        "Category":    "Suspicious",
        "Explanation": "Promises unrealistic returns (40% monthly). Unsolicited investment offer — common fraud indicator.",
    },
    {
        "Subject": "Survey: Share your opinion and earn rewards",
        "Sender":  "survey@quickrewards-panel.com",
        "Body": (
            "You qualify for a paid consumer survey. Complete it in 5 minutes and earn a $50 voucher. "
            "Start here: http://quickrewards-panel.com/survey?id=4821"
        ),
        "Category":    "Suspicious",
        "Explanation": "Reward-for-survey pattern commonly used to collect personal data. Unsolicited sender.",
    },
    {
        "Subject": "Verify your email to complete registration",
        "Sender":  "noreply@unknownservice-verify.net",
        "Body": (
            "Thank you for registering with us. Please verify your email address by clicking the link below. "
            "Verification link: http://unknownservice-verify.net/verify?token=TK9921"
        ),
        "Category":    "Suspicious",
        "Explanation": "Verification email from an unrecognised service the user never signed up to.",
    },
    # ── Safe (7) ──────────────────────────────────────────────────────────────
    {
        "Subject": "Your order #ORD-20481 has been shipped",
        "Sender":  "orders@example-shop.com",
        "Body": (
            "Hi Alex, great news — your order #ORD-20481 has been dispatched. "
            "Estimated delivery: 3–5 business days. "
            "Track your parcel at: https://example-shop.com/track/ORD-20481"
        ),
        "Category":    "Safe",
        "Explanation": "Standard transactional shipping notification with a branded domain and order reference.",
    },
    {
        "Subject": "Meeting notes — Q3 planning session",
        "Sender":  "alice.johnson@acmecorp.com",
        "Body": (
            "Hi team, please find the notes from today's Q3 planning session attached. "
            "Key action items are listed on page 2. Our next sync is scheduled for Tuesday at 10am. "
            "Best, Alice"
        ),
        "Category":    "Safe",
        "Explanation": "Internal business email with a legitimate corporate domain, no links, natural language.",
    },
    {
        "Subject": "Your monthly bank statement is ready",
        "Sender":  "statements@firstnationalbank.com",
        "Body": (
            "Dear customer, your statement for July 2025 is now available. "
            "Log in to your online banking portal at https://firstnationalbank.com/login to view it. "
            "If you have any questions, call us on 0800-555-0100."
        ),
        "Category":    "Safe",
        "Explanation": "Routine bank statement notification. Directs to the official domain; provides a phone number.",
    },
    {
        "Subject": "Password reset request for your account",
        "Sender":  "no-reply@github.com",
        "Body": (
            "Hi there, we received a request to reset your GitHub password. "
            "If you made this request, click the link below. It will expire in 1 hour. "
            "https://github.com/password_reset/abc987xyz"
        ),
        "Category":    "Safe",
        "Explanation": "Legitimate password reset from a known platform. Official domain, short expiry, no pressure.",
    },
    {
        "Subject": "Your weekly newsletter — Tech Digest #44",
        "Sender":  "digest@techdigest-weekly.com",
        "Body": (
            "This week in tech: AI chip shortages, the latest open-source LLM releases, and a roundup of "
            "cybersecurity news. Read the full issue at https://techdigest-weekly.com/issue/44. "
            "Unsubscribe: https://techdigest-weekly.com/unsubscribe"
        ),
        "Category":    "Safe",
        "Explanation": "Opted-in newsletter with consistent branding, no urgency, and a visible unsubscribe link.",
    },
    {
        "Subject": "Invitation to Alice's birthday party 🎉",
        "Sender":  "alice.smith@gmail.com",
        "Body": (
            "Hey! You're invited to my birthday party on Saturday the 12th at 7pm. "
            "It's at The Blue Door restaurant on Main Street. Let me know if you can make it! "
            "Looking forward to seeing you, Alice"
        ),
        "Category":    "Safe",
        "Explanation": "Personal email from a known individual using a reputable provider. No links, no data requests.",
    },
    {
        "Subject": "Your flight booking confirmation — Flight DL4821",
        "Sender":  "bookings@flyexample-airlines.com",
        "Body": (
            "Dear passenger, your booking is confirmed. "
            "Flight: DL4821 | Date: 15 Aug 2025 | Seat: 22A. "
            "Manage your booking at https://flyexample-airlines.com/manage/DL4821. "
            "Have a great trip!"
        ),
        "Category":    "Safe",
        "Explanation": "Standard flight confirmation with booking reference and branded domain. No suspicious elements.",
    },
]

# Map category name → badge CSS class and display label
CATEGORY_META = {
    "Phishing":   {"badge": "badge-phishing",   "icon": "🔴", "label": "Phishing"},
    "Suspicious": {"badge": "badge-suspicious", "icon": "🟡", "label": "Suspicious"},
    "Safe":       {"badge": "badge-safe",       "icon": "🟢", "label": "Safe"},
}


# =============================================================================
# CHART HELPERS
# =============================================================================

# Shared colour constants so every chart matches the dark theme
_CHART_BG = "#0d1117"   # main page background
_PAPER_BG = "#161b22"   # card / panel background
_GRID_COL = "#30363d"   # grid lines
_FONT_COL = "#8b949e"   # axis labels and legend text


def _chart_layout(title: str = "") -> dict:
    """Return a base Plotly layout dict styled for the dark theme."""
    return dict(
        title=dict(text=title, font=dict(color="#e6edf3", size=14)),
        paper_bgcolor=_PAPER_BG,
        plot_bgcolor=_CHART_BG,
        font=dict(color=_FONT_COL, size=12),
        margin=dict(l=20, r=20, t=40, b=20),
        showlegend=True,
        legend=dict(
            bgcolor=_PAPER_BG,
            bordercolor=_GRID_COL,
            borderwidth=1,
            font=dict(color="#e6edf3"),
        ),
    )


def make_risk_distribution_chart(n_high: int, n_medium: int, n_low: int) -> go.Figure:
    """
    Donut chart showing how emails are split across the three risk levels.
    """
    fig = go.Figure(
        go.Pie(
            labels=["High Risk", "Medium Risk", "Low Risk"],
            values=[n_high, n_medium, n_low],
            hole=0.55,   # hollow centre = donut shape
            marker=dict(
                colors=["#f85149", "#d29922", "#3fb950"],
                line=dict(color=_CHART_BG, width=2),
            ),
            textinfo="label+percent",
            textfont=dict(color="#e6edf3", size=12),
            hovertemplate="%{label}: %{value} email(s) (%{percent})<extra></extra>",
        )
    )
    layout = _chart_layout("Risk Level Distribution")
    layout["legend"]["orientation"] = "h"
    layout["legend"]["y"] = -0.15
    fig.update_layout(**layout)
    return fig


def make_risk_bar_chart(n_high: int, n_medium: int, n_low: int) -> go.Figure:
    """
    Vertical bar chart: one bar per risk level, labelled with the count.
    """
    fig = go.Figure(
        go.Bar(
            x=["High Risk", "Medium Risk", "Low Risk"],
            y=[n_high, n_medium, n_low],
            marker_color=["#f85149", "#d29922", "#3fb950"],
            text=[n_high, n_medium, n_low],
            textposition="outside",
            textfont=dict(color="#e6edf3"),
            hovertemplate="%{x}: %{y} email(s)<extra></extra>",
        )
    )
    layout = _chart_layout("Emails by Risk Level")
    layout["yaxis"] = dict(
        gridcolor=_GRID_COL,
        title="Count",
        title_font=dict(color=_FONT_COL),
        tickcolor=_FONT_COL,
    )
    layout["xaxis"] = dict(tickcolor=_FONT_COL)
    layout["showlegend"] = False
    fig.update_layout(**layout)
    return fig


# =============================================================================
# RESULT-BOX RENDERER
# =============================================================================

def _render_results(result: dict) -> None:
    """
    Draw the full analysis result card inside the Streamlit page.

    Parameters
    ----------
    result : dict   Returned by analyse_email().
                    Keys: score, level, level_class, indicators.
    """
    score       = result["score"]
    level       = result["level"]
    level_class = result["level_class"]
    indicators  = result["indicators"]

    # Pick a colour based on the risk level
    if score >= 70:
        bar_colour = "#f85149"
    elif score >= 40:
        bar_colour = "#d29922"
    else:
        bar_colour = "#3fb950"

    # ── Gauge bar ─────────────────────────────────────────────────────────────
    # A horizontal bar that fills proportionally to the risk score.
    gauge_html = (
        f"<div style='background:#21262d; border-radius:6px; height:10px; "
        f"margin-top:6px; overflow:hidden;'>"
        f"  <div style='width:{score}%; background:{bar_colour}; "
        f"  height:100%; border-radius:6px;'></div>"
        f"</div>"
    )

    # ── Indicator cards ───────────────────────────────────────────────────────
    # One card per matched rule showing the rule name, point value, and why it matters.
    if indicators:
        rows = ""
        for ind in indicators:
            rows += (
                f"<div style='border-left:3px solid {bar_colour}; "
                f"padding:10px 14px; margin-bottom:10px; "
                f"background:#1c2128; border-radius:0 6px 6px 0;'>"
                f"  <div style='font-weight:600; color:#e6edf3; margin-bottom:4px;'>"
                f"    ⚠️ {ind['name']} "
                f"    <span style='font-size:11px; color:{bar_colour}; font-weight:400;'>"
                f"      +{ind['points']} pts</span>"
                f"  </div>"
                f"  <div style='font-size:13px; color:#8b949e;'>{ind['explanation']}</div>"
                f"</div>"
            )
        indicators_html = rows
    else:
        indicators_html = (
            "<div style='color:#3fb950; font-size:14px;'>"
            "✅ No phishing indicators detected in this email."
            "</div>"
        )

    # ── Disclaimer ────────────────────────────────────────────────────────────
    disclaimer = (
        "<div style='margin-top:20px; padding:12px 16px; background:#21262d; "
        "border-radius:8px; border:1px solid #30363d; font-size:12px; color:#8b949e;'>"
        "⚠️ <strong>Disclaimer:</strong> This result is an automated estimate based on "
        "text patterns only. It is <em>not</em> a guarantee. Legitimate emails can "
        "sometimes trigger indicators, and sophisticated phishing emails may evade "
        "detection. Always apply your own judgement and report suspicious emails to "
        "your organisation's security team."
        "</div>"
    )

    st.markdown(
        f"<div class='result-box'>"
        f"  <div style='display:flex; gap:48px; flex-wrap:wrap; margin-bottom:20px;'>"
        f"    <div>"
        f"      <div class='result-label'>Risk Level</div>"
        f"      <div class='result-value {level_class}'>{level}</div>"
        f"    </div>"
        f"    <div style='flex:1; min-width:160px;'>"
        f"      <div class='result-label'>Risk Score</div>"
        f"      <div class='result-value {level_class}'>{score} / 100</div>"
        f"      {gauge_html}"
        f"    </div>"
        f"  </div>"
        f"  <div class='result-label' style='margin-bottom:12px;'>"
        f"    Detected Indicators ({len(indicators)} found)"
        f"  </div>"
        f"  {indicators_html}"
        f"  {disclaimer}"
        f"</div>",
        unsafe_allow_html=True,
    )


# =============================================================================
# STREAMLIT PAGE SETUP
# =============================================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
        /* ── Page background ── */
        .stApp {
            background-color: #0d1117;
            color: #e6edf3;
        }

        /* ── Summary cards ── */
        .card {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px 24px;
            text-align: center;
        }
        .card-title {
            font-size: 13px;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 8px;
        }
        .card-value  { font-size: 36px; font-weight: 700; line-height: 1; }
        .card-total  { color: #58a6ff; }
        .card-phish  { color: #f85149; }
        .card-sus    { color: #d29922; }
        .card-safe   { color: #3fb950; }

        /* ── Section headers ── */
        .section-header {
            font-size: 18px;
            font-weight: 600;
            color: #58a6ff;
            border-bottom: 1px solid #30363d;
            padding-bottom: 8px;
            margin-bottom: 16px;
        }

        /* ── Analysis result box ── */
        .result-box {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 24px;
        }
        .result-label {
            font-size: 12px;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }
        .result-value { font-size: 22px; font-weight: 700; margin-top: 4px; }
        .risk-high    { color: #f85149; }
        .risk-medium  { color: #d29922; }
        .risk-low     { color: #3fb950; }

        /* ── Text inputs ─────────────────────────────────────────────────────
           Subject field (single-line): white text on dark background.
           Body field (textarea): black text on dark background. */
        .stTextInput > div > div > input {
            background-color: #161b22 !important;
            color: #ffffff !important;
            border: 1px solid #30363d !important;
            border-radius: 8px !important;
        }
        
        .stTextArea textarea,
        .stTextArea textarea:focus {
            background-color: #ffffff !important;
            color: #000000 !important;
            -webkit-text-fill-color: #000000 !important;
            border: 1px solid #30363d !important;
            border-radius: 8px !important;
        }


        /* ── Buttons ── */
        .stButton > button {
            background-color: #238636;
            color: #ffffff;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            padding: 10px 32px;
            width: 100%;
        }
        .stButton > button:hover { background-color: #2ea043; }

        /* ── Email tables ── */
        .email-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        .email-table th {
            background-color: #21262d;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            font-size: 11px;
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }
        .email-table td {
            padding: 10px 14px;
            border-bottom: 1px solid #21262d;
            vertical-align: top;
            color: #e6edf3;
        }
        .email-table tr:last-child td { border-bottom: none; }
        .email-table tr:hover td     { background-color: #1c2128; }

        /* ── Category / risk-level badges ── */
        .badge {
            display: inline-block;
            border-radius: 20px;
            padding: 3px 12px;
            font-size: 12px;
            font-weight: 600;
            white-space: nowrap;
        }
        .badge-phishing   { background-color:#3d1a1a; color:#f85149; border:1px solid #f85149; }
        .badge-suspicious { background-color:#2d2208; color:#d29922; border:1px solid #d29922; }
        .badge-safe       { background-color:#0f2d1a; color:#3fb950; border:1px solid #3fb950; }

        /* ── High-Risk alert cards ── */
        .alert-panel   { background-color:#2d1010; border:1px solid #f85149;
                         border-radius:10px; padding:16px 20px; margin-bottom:12px; }
        .alert-title   { font-weight:700; color:#f85149; font-size:14px; margin-bottom:6px; }
        .alert-subject { color:#e6edf3; font-size:13px; margin-bottom:4px; }
        .alert-meta    { color:#8b949e; font-size:12px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# =============================================================================
# SESSION STATE  (persists values between Streamlit reruns)
# =============================================================================

# Has the user clicked "Generate Sample Emails"?
if "sample_generated" not in st.session_state:
    st.session_state.sample_generated = False

# List of every email the user has analysed this session.
# Each entry: { subject, level, score, indicators }
if "history" not in st.session_state:
    st.session_state.history = []

# The most recent analysis result dict (keeps the result box visible after rerun).
if "last_result" not in st.session_state:
    st.session_state.last_result = None

# Two-step clear-history confirmation flag.
if "confirm_clear" not in st.session_state:
    st.session_state.confirm_clear = False


# =============================================================================
# PAGE LAYOUT
# =============================================================================

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("# 🛡️ PhishGuard AI")
st.markdown(
    "<p style='color:#8b949e; font-size:15px; margin-top:-12px;'>"
    "AI-powered phishing email detection — paste any email and get an instant risk assessment."
    "</p>",
    unsafe_allow_html=True,
)
st.markdown("<hr style='border-color:#30363d; margin:16px 0 24px;'>", unsafe_allow_html=True)


# ── Compute live dashboard counts ─────────────────────────────────────────────
hist     = st.session_state.history
n_high   = sum(1 for e in hist if e["level"] == "High Risk")
n_medium = sum(1 for e in hist if e["level"] == "Medium Risk")
n_low    = sum(1 for e in hist if e["level"] == "Low Risk")

# Add sample-dataset counts on top when the sample has been generated.
n_sample_phish = n_sample_sus = n_sample_safe = 0
if st.session_state.sample_generated:
    n_sample_phish = sum(1 for e in SAMPLE_EMAILS if e["Category"] == "Phishing")
    n_sample_sus   = sum(1 for e in SAMPLE_EMAILS if e["Category"] == "Suspicious")
    n_sample_safe  = sum(1 for e in SAMPLE_EMAILS if e["Category"] == "Safe")

total      = len(hist) + (len(SAMPLE_EMAILS) if st.session_state.sample_generated else 0)
phishing   = n_high   + n_sample_phish
suspicious = n_medium + n_sample_sus
safe_count = n_low    + n_sample_safe

# On first load (nothing analysed yet) show welcoming placeholder numbers so
# the dashboard doesn't appear empty.
using_placeholder = (total == 0)
if using_placeholder:
    total, phishing, suspicious, safe_count = 128, 47, 23, 58
    chart_high, chart_medium, chart_low     = 47, 23, 58
else:
    # Charts reflect actual counts; if sample emails are included, use totals.
    if st.session_state.sample_generated:
        chart_high, chart_medium, chart_low = phishing, suspicious, safe_count
    else:
        chart_high, chart_medium, chart_low = n_high, n_medium, n_low


# ── Summary cards ─────────────────────────────────────────────────────────────
st.markdown("<div class='section-header'>📊 Dashboard Overview</div>", unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(
        f"<div class='card'><div class='card-title'>Total Analysed</div>"
        f"<div class='card-value card-total'>{total}</div></div>",
        unsafe_allow_html=True,
    )
with c2:
    st.markdown(
        f"<div class='card'><div class='card-title'>High Risk (Phishing)</div>"
        f"<div class='card-value card-phish'>{phishing}</div></div>",
        unsafe_allow_html=True,
    )
with c3:
    st.markdown(
        f"<div class='card'><div class='card-title'>Medium Risk (Suspicious)</div>"
        f"<div class='card-value card-sus'>{suspicious}</div></div>",
        unsafe_allow_html=True,
    )
with c4:
    st.markdown(
        f"<div class='card'><div class='card-title'>Low Risk (Safe)</div>"
        f"<div class='card-value card-safe'>{safe_count}</div></div>",
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)


# ── Visualisation charts ──────────────────────────────────────────────────────
st.markdown("<div class='section-header'>📈 Risk Visualisations</div>", unsafe_allow_html=True)

ch1, ch2 = st.columns(2)
with ch1:
    fig_donut = make_risk_distribution_chart(chart_high, chart_medium, chart_low)
    st.plotly_chart(fig_donut, use_container_width=True, config={"displayModeBar": False})  # noqa: deprecated-but-still-works

with ch2:
    fig_bar = make_risk_bar_chart(chart_high, chart_medium, chart_low)
    st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar": False})  # noqa: deprecated-but-still-works

if using_placeholder:
    st.markdown(
        "<p style='color:#8b949e; font-size:12px; text-align:center; margin-top:-8px;'>"
        "Charts show demo data. Analyse an email or generate sample emails to see live results."
        "</p>",
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)


# ── High Risk alert panel ─────────────────────────────────────────────────────
# Only shown when the user has personally analysed at least one High Risk email.
high_risk_entries = [e for e in hist if e["level"] == "High Risk"]

if high_risk_entries:
    st.markdown(
        "<div class='section-header'>🚨 High Risk Alerts</div>",
        unsafe_allow_html=True,
    )
    for entry in high_risk_entries:
        ind_text = ", ".join(entry["indicators"]) if entry["indicators"] else "None"
        st.markdown(
            f"<div class='alert-panel'>"
            f"  <div class='alert-title'>🔴 HIGH RISK EMAIL DETECTED</div>"
            f"  <div class='alert-subject'><strong>{entry['subject']}</strong></div>"
            f"  <div class='alert-meta'>"
            f"    Score: {entry['score']} / 100 &nbsp;|&nbsp; Indicators: {ind_text}"
            f"  </div>"
            f"</div>",
            unsafe_allow_html=True,
        )
    st.markdown("<br>", unsafe_allow_html=True)


# ── Email input ───────────────────────────────────────────────────────────────
st.markdown("<div class='section-header'>📧 Analyse an Email</div>", unsafe_allow_html=True)

email_subject = st.text_input(
    "Email Subject",
    placeholder="e.g. Urgent: Your account has been compromised — verify now!",
)
email_body = st.text_area(
    "Email Body",
    placeholder="Paste the full email body here…",
    height=220,
)
analyze_clicked = st.button("🔍 Analyze Email")

st.markdown("<br>", unsafe_allow_html=True)


# ── Analysis results ──────────────────────────────────────────────────────────
st.markdown("<div class='section-header'>📋 Analysis Results</div>", unsafe_allow_html=True)

if analyze_clicked:
    if not email_subject.strip() and not email_body.strip():
        # Guard: refuse to analyse empty input
        st.warning("Please enter an email subject or body before analysing.")
    else:
        # Run detection
        result    = analyse_email(email_subject, body=email_body)
        ind_names = [ind["name"] for ind in result["indicators"]]

        # Store in history (newest entries appear first in the table)
        st.session_state.history.append({
            "subject":    email_subject,
            "level":      result["level"],
            "score":      result["score"],
            "indicators": ind_names,
        })
        st.session_state.last_result = result

        # Rerun so dashboard counts and charts update immediately
        st.rerun()

# Show the result of the most recent analysis (survives reruns via session state)
if st.session_state.last_result is not None:
    _render_results(st.session_state.last_result)
else:
    st.markdown(
        "<div class='result-box' style='text-align:center; padding:40px;'>"
        "<span style='color:#8b949e; font-size:15px;'>"
        "Enter an email above and click <strong>Analyze Email</strong> to see results."
        "</span></div>",
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)


# ── Analysis history table ────────────────────────────────────────────────────
# Shown only after the user has analysed at least one email manually.
if hist:
    st.markdown(
        "<div class='section-header'>🗂️ Analysis History</div>",
        unsafe_allow_html=True,
    )

    rows_html = ""
    for i, entry in enumerate(reversed(hist), start=1):   # newest = row 1
        level = entry["level"]

        if level == "High Risk":
            badge_cls, icon = "badge-phishing",   "🔴"
        elif level == "Medium Risk":
            badge_cls, icon = "badge-suspicious", "🟡"
        else:
            badge_cls, icon = "badge-safe",       "🟢"

        badge_html = f"<span class='badge {badge_cls}'>{icon} {level}</span>"
        ind_text   = ", ".join(entry["indicators"]) if entry["indicators"] else "—"
        score_val  = entry.get("score", "—")

        rows_html += (
            f"<tr>"
            f"<td style='color:#8b949e; width:32px;'>{i}</td>"
            f"<td><strong>{entry['subject']}</strong></td>"
            f"<td>{badge_html}</td>"
            f"<td style='color:#e6edf3; text-align:center;'>{score_val}</td>"
            f"<td style='color:#8b949e; font-size:12px;'>{ind_text}</td>"
            f"</tr>"
        )

    st.markdown(
        "<div style='background-color:#161b22; border:1px solid #30363d; "
        "border-radius:10px; overflow:hidden; margin-bottom:16px;'>"
        "<table class='email-table'><thead><tr>"
        "<th>#</th><th>Subject</th><th>Risk Level</th>"
        "<th style='text-align:center;'>Score</th><th>Detected Indicators</th>"
        f"</tr></thead><tbody>{rows_html}</tbody></table></div>",
        unsafe_allow_html=True,
    )

    # ── Clear History (two-step confirmation) ─────────────────────────────────
    cl1, cl2, cl3 = st.columns([2, 2, 2])

    if not st.session_state.confirm_clear:
        with cl1:
            if st.button("🗑️ Clear History"):
                st.session_state.confirm_clear = True
                st.rerun()
    else:
        st.warning("Are you sure you want to clear all analysis history? This cannot be undone.")
        with cl2:
            if st.button("✅ Yes, clear history"):
                st.session_state.history       = []
                st.session_state.last_result   = None
                st.session_state.confirm_clear = False
                st.rerun()
        with cl3:
            if st.button("❌ Cancel"):
                st.session_state.confirm_clear = False
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)


# ── Sample email generator ────────────────────────────────────────────────────
st.markdown("<div class='section-header'>🧪 Sample Email Dataset</div>", unsafe_allow_html=True)
st.markdown(
    "<p style='color:#8b949e; font-size:14px; margin-bottom:16px;'>"
    "Generate 22 fictional test emails — a mix of phishing, suspicious, and safe messages — "
    "to explore how PhishGuard AI classifies different email types."
    "</p>",
    unsafe_allow_html=True,
)

if st.button("⚡ Generate Sample Emails"):
    st.session_state.sample_generated = True
    st.rerun()

if st.session_state.sample_generated:
    # Legend
    st.markdown(
        "<div style='display:flex; gap:16px; margin-bottom:16px; flex-wrap:wrap;'>"
        "<span class='badge badge-phishing'>🔴 Phishing</span>"
        "<span class='badge badge-suspicious'>🟡 Suspicious</span>"
        "<span class='badge badge-safe'>🟢 Safe</span>"
        "</div>",
        unsafe_allow_html=True,
    )

    # Build sample table
    rows_html = ""
    for i, email in enumerate(SAMPLE_EMAILS, start=1):
        meta       = CATEGORY_META[email["Category"]]
        badge_html = f"<span class='badge {meta['badge']}'>{meta['icon']} {meta['label']}</span>"
        rows_html += (
            f"<tr>"
            f"<td style='color:#8b949e; width:36px;'>{i}</td>"
            f"<td>{badge_html}</td>"
            f"<td><strong>{email['Subject']}</strong></td>"
            f"<td style='color:#8b949e;'>{email['Sender']}</td>"
            f"<td style='color:#8b949e; font-size:12px;'>{email['Explanation']}</td>"
            f"</tr>"
        )

    st.markdown(
        "<div style='background-color:#161b22; border:1px solid #30363d; border-radius:10px; "
        "overflow:hidden; margin-bottom:24px;'>"
        "<table class='email-table'><thead><tr>"
        "<th>#</th><th>Category</th><th>Subject</th><th>Sender</th><th>Why this category?</th>"
        f"</tr></thead><tbody>{rows_html}</tbody></table></div>",
        unsafe_allow_html=True,
    )

    # Category breakdown bar — guard against division by zero
    if total > 0:
        phish_pct = round(phishing   / total * 100)
        sus_pct   = round(suspicious / total * 100)
        safe_pct  = round(safe_count / total * 100)
    else:
        phish_pct = sus_pct = safe_pct = 0

    st.markdown(
        f"<div style='background-color:#161b22; border:1px solid #30363d; "
        f"border-radius:10px; padding:20px;'>"
        f"<div class='result-label' style='margin-bottom:12px;'>"
        f"Category Breakdown — {total} emails</div>"
        f"<div style='display:flex; border-radius:6px; overflow:hidden; "
        f"height:20px; margin-bottom:12px;'>"
        f"  <div style='width:{phish_pct}%; background-color:#f85149;'></div>"
        f"  <div style='width:{sus_pct}%;   background-color:#d29922;'></div>"
        f"  <div style='width:{safe_pct}%;  background-color:#3fb950;'></div>"
        f"</div>"
        f"<div style='display:flex; gap:24px; font-size:13px; flex-wrap:wrap;'>"
        f"  <span style='color:#f85149;'>🔴 Phishing: {phishing} ({phish_pct}%)</span>"
        f"  <span style='color:#d29922;'>🟡 Suspicious: {suspicious} ({sus_pct}%)</span>"
        f"  <span style='color:#3fb950;'>🟢 Safe: {safe_count} ({safe_pct}%)</span>"
        f"</div></div>",
        unsafe_allow_html=True,
    )


# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown(
    "<hr style='border-color:#30363d; margin-top:40px;'>"
    "<p style='text-align:center; color:#8b949e; font-size:12px;'>"
    "PhishGuard AI &nbsp;·&nbsp; Built with Python &amp; Streamlit"
    "</p>",
    unsafe_allow_html=True,
)

# Email Security Checker

A small tool that checks whether an organization's email domain is protected
against **spoofing** (criminals sending email that looks like it came from you).
It checks the three DNS records that control this (**SPF**, **DKIM**, and
**DMARC**), explains any problems in plain English, and gives a letter grade.

Built for nonprofits and small organizations using Google Workspace or
Microsoft 365.

## What's in this project

| File | What it is |
|---|---|
| `email_checker.py` | The checker tool |
| `README.md` | This guide, including a step-by-step walk-through for fixing problems |
| `Email_Authentication_Policy.docx` | A policy template nonprofits can adopt that requires SPF, DKIM, and DMARC |
| `report.html` | A sample HTML report (microsoft.com) |

---

## How to run it

Requires Python 3.8 or newer. No extra packages needed.

**Download it:** click the green **Code** button on this page → **Download ZIP**,
then unzip it. Or, with git:

```bash
git clone https://github.com/matthewpellegrino999-hash/email-security-checker.git
cd email-security-checker
```

**Run it:**

```bash
python3 email_checker.py yourorg.org
```

Or open `email_checker.py` in IDLE and choose **Run → Run Module** (F5). It will ask
for the domain to check and whether to save an HTML report.

Save a shareable HTML report:

```bash
python3 email_checker.py yourorg.org --html report.html
```

If you know your DKIM selector (see "Finding your DKIM selector" below):

```bash
python3 email_checker.py yourorg.org --selector myselector
```

---

## What the three records do

| Record | Plain-English meaning | Where it lives |
|--------|----------------------|----------------|
| **SPF** | "These are the only servers allowed to send email for my domain." | TXT record at `yourorg.org` |
| **DKIM** | A digital signature on every email, proving it wasn't faked or changed. | TXT record at `selector._domainkey.yourorg.org` |
| **DMARC** | "If an email fails SPF/DKIM, here's what to do with it, and send me a report." | TXT record at `_dmarc.yourorg.org` |

Without all three, anyone can send email "from" your CEO or finance team, which
is the most common way nonprofits lose money to fraud.

---

## Walk-through: fixing your setup

Follow this **after** the checker finds problems. Do the steps in order.

**Where the changes happen:** all fixes are made in your domain's **DNS
settings**, on the website of the company you bought the domain from (GoDaddy,
Namecheap, Cloudflare, Squarespace, etc.). Log in, find "DNS settings," and add
or edit records. A DNS record is one line in your domain's public settings list.

---

### Step 1: SPF (the guest list)

**Goal:** tell the world which servers are allowed to send email for your domain.

**What to do:** add **one** TXT record (host `@`) and paste in the text for your
email provider:

| Your email provider | Text to paste |
|---|---|
| Google Workspace | `v=spf1 include:_spf.google.com ~all` |
| Microsoft 365 | `v=spf1 include:spf.protection.outlook.com -all` |
| Domain doesn't send email | `v=spf1 -all` |

**What that text means:**
- `v=spf1` means "this is an SPF record."
- `include:_spf.google.com` means "Google's servers are allowed."
- `~all` or `-all` means "everyone else is not allowed."

**Important rule:** only **one** SPF record per domain. If you also use
Mailchimp, Constant Contact, or a donation site, add it to the **same** record
instead of making a second one. Two SPF records break SPF completely.

---

### Step 2: DKIM (the wax seal)

**Goal:** turn on digital signatures for your outgoing email.

**What to do:** this step starts in your **email admin panel**, not DNS. Your
email provider creates the keys, you post the public key in DNS, then you
switch signing on.

- **Google Workspace:** Admin console → Apps → Google Workspace → Gmail →
  Authenticate email → click **Generate new record**. Copy the record Google
  gives you into DNS, then click **Start authentication**.
- **Microsoft 365:** Microsoft Defender portal → Email & collaboration →
  Policies → Threat policies → Email authentication settings → DKIM → select
  your domain. Add the two records Microsoft gives you to DNS, then click
  **Enable**.

---

### Step 3: DMARC (the bouncer), done slowly

**Goal:** tell email providers to block fake email, without accidentally
blocking your real email.

**What to do:** add a TXT record with host `_dmarc`, then change it over time:

| When | Text to use | What happens |
|---|---|---|
| Weeks 1–4 | `v=DMARC1; p=none; rua=mailto:dmarc@yourorg.org` | **Watch only.** Nothing is blocked. You get reports showing everyone sending email as your domain. |
| Once reports look clean | change `p=none` to `p=quarantine` | Fake email goes to **spam**. |
| A few weeks later | change to `p=reject` | Fake email is **blocked** completely. |

**Why go slowly?** Organizations often forget about services that send email
for them, like a newsletter tool or donation receipts. The reports from the
watch phase reveal those so you can add them to SPF first. Otherwise you would
block your own real email.

**What `rua=` is:** the email address where daily reports get sent. Free tools
like dmarcian or Postmark's DMARC digests make the reports easier to read.

---

### Step 4: Re-check

**Goal:** confirm the fixes worked.

**What to do:** wait about an hour (sometimes up to 2 days) for DNS changes to
take effect, then run the checker again. Aim for grade **A**.

---

**The whole process in one line:** run the checker to find problems → follow
Steps 1–3 to fix them in DNS → run the checker again to confirm.

---

## Finding your DKIM selector

The checker tries common selector names automatically. If yours isn't found:

1. Open any email sent from your domain.
2. View the original message (Gmail: ⋮ → *Show original*; Outlook: *View
   message source*).
3. Find the line starting with `DKIM-Signature:` and look for `s=`. That value
   is your selector.

---

## How the grade works

| Grade | Meaning |
|---|---|
| A | No failures or warnings |
| B | No failures, 1–2 warnings |
| C | 1 failure, or several warnings |
| D | 2–3 failures |
| F | 4+ failures |

---

## How it works (technical)

- DNS lookups are made with Cloudflare's public DNS-over-HTTPS API using only
  the Python standard library, so it runs the same on macOS, Windows, and
  Linux.
- SPF: checks for exactly one record, the strictness of the `all` mechanism,
  the 10-lookup limit, and deprecated `ptr` usage.
- DKIM: tries about 20 common selectors from Google, Microsoft, Yahoo, and popular email
  services, and detects revoked (empty) keys.
- DMARC: checks the policy (`none` / `quarantine` / `reject`), `pct`, and
  whether reporting (`rua`) is configured.
- Recognizes "parked" domains that correctly declare they send no email
  (`v=spf1 -all` and a null MX record).

**Limitations:** DKIM detection can't find custom selector names without
`--selector`. SPF lookup counting only counts the top-level record, not nested
includes.

---

## Author and license

Created by Matthew Pellegrino as a cybersecurity capstone project (October 2026).
Released under the [MIT License](LICENSE): free to use, share, and modify.

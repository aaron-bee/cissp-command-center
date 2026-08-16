from datetime import date, datetime, timedelta
from math import ceil
import hmac
import os

from flask import Flask, flash, redirect, render_template, request, session, url_for

from database import get_db_connection, initialize_database


app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "certification-command-center-local-dev",
)


VALID_CERTIFICATIONS = {"CISSP", "CISM"}

CERTIFICATION_CONFIG = {
    "CISSP": {
        "sample_target": 150,
        "green_accuracy": 80,
        "mock_target": 80,
        "domain_count": 8,
    },
    "CISM": {
        "sample_target": 100,
        "green_accuracy": 80,
        "mock_target": 80,
        "domain_count": 4,
    },
}


def dashboard_auth_configured():
    return bool(os.environ.get("DASHBOARD_PASSWORD"))


@app.before_request
def require_dashboard_login():
    if request.endpoint in {"login", "logout", "health", "static"}:
        return None

    if not dashboard_auth_configured():
        return None

    if session.get("dashboard_authenticated"):
        return None

    return redirect(
        url_for(
            "login",
            next=request.full_path if request.query_string else request.path,
        )
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if not dashboard_auth_configured():
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        expected_username = os.environ.get("DASHBOARD_USERNAME", "admin")
        expected_password = os.environ.get("DASHBOARD_PASSWORD", "")
        supplied_username = request.form.get("username", "")
        supplied_password = request.form.get("password", "")

        username_ok = hmac.compare_digest(
            supplied_username,
            expected_username,
        )
        password_ok = hmac.compare_digest(
            supplied_password,
            expected_password,
        )

        if username_ok and password_ok:
            session.clear()
            session["dashboard_authenticated"] = True

            next_url = request.form.get("next", "")
            if (
                next_url
                and next_url.startswith("/")
                and not next_url.startswith("//")
            ):
                return redirect(next_url)

            return redirect(url_for("dashboard"))

        error = "Invalid username or password."

    return render_template(
        "login.html",
        error=error,
        next_url=request.args.get("next", ""),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}, 200


def get_active_certification():
    certification = request.args.get("cert", "CISSP").upper()
    return certification if certification in VALID_CERTIFICATIONS else "CISSP"


def parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def days_until(value):
    target = parse_date(value)
    return (target - date.today()).days if target else None


def format_date(value):
    if not value:
        return "Not set"
    if isinstance(value, str):
        value = parse_date(value)
    return value.strftime("%b %d, %Y") if value else "Not set"


def get_settings(connection):
    rows = connection.execute("SELECT key, value FROM settings").fetchall()
    return {row["key"]: row["value"] for row in rows}


def get_historical_attempt(connection, certification):
    attempt = connection.execute(
        """
        SELECT id, certification, attempt_period, overall_score, result
        FROM certification_attempts
        WHERE certification = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (certification,),
    ).fetchone()

    if not attempt:
        return None

    domain_rows = connection.execute(
        """
        SELECT d.id, d.domain_number, d.name, d.weight, r.scaled_score
        FROM attempt_domain_results r
        JOIN domains d ON d.id = r.domain_id
        WHERE r.attempt_id = ?
        ORDER BY d.domain_number
        """,
        (attempt["id"],),
    ).fetchall()

    domains = []
    for row in domain_rows:
        score = row["scaled_score"]
        gap_to_reference = max(450 - score, 0)
        weighted_gap = round(gap_to_reference * (row["weight"] / 100), 2)

        if score >= 450:
            historical_status = "ABOVE REFERENCE"
        elif score >= 425:
            historical_status = "CLOSE"
        elif score >= 400:
            historical_status = "BELOW"
        else:
            historical_status = "WEAK"

        visual_percent = round(
            max(min((score - 200) / 600 * 100, 100), 0),
            1,
        )
        pass_marker_percent = round((450 - 200) / 600 * 100, 1)

        domains.append(
            {
                "id": row["id"],
                "number": row["domain_number"],
                "name": row["name"],
                "weight": row["weight"],
                "score": score,
                "gap": gap_to_reference,
                "weighted_gap": weighted_gap,
                "historical_status": historical_status,
                "visual_percent": visual_percent,
                "pass_marker_percent": pass_marker_percent,
            }
        )

    ranked = sorted(
        domains,
        key=lambda item: item["weighted_gap"],
        reverse=True,
    )

    return {
        "period": attempt["attempt_period"],
        "overall_score": attempt["overall_score"],
        "result": attempt["result"],
        "reference_score": 450,
        "domains": domains,
        "priority": ranked[0] if ranked else None,
        "ranked": ranked,
    }


def calculate_color_status(accuracy, questions):
    if questions == 0:
        return "UNTESTED"
    if accuracy < 70:
        return "RED"
    if accuracy < 80:
        return "YELLOW"
    return "GREEN"


def calculate_readiness_status(certification, accuracy, questions):
    target = CERTIFICATION_CONFIG[certification]["sample_target"]

    if questions == 0:
        return "UNTESTED"
    if questions < 50:
        return "LOW SAMPLE"
    if questions < target:
        return "BUILDING"
    if accuracy < 80:
        return "REMEDIATE"
    return "READY"


def build_domains(connection, certification):
    rows = connection.execute(
        """
        SELECT id, domain_number, certification, name, weight,
               questions_answered, questions_correct
        FROM domains
        WHERE certification = ?
        ORDER BY domain_number
        """,
        (certification,),
    ).fetchall()

    target = CERTIFICATION_CONFIG[certification]["sample_target"]
    domains = []

    for row in rows:
        questions = row["questions_answered"]
        correct = row["questions_correct"]
        accuracy = round((correct / questions) * 100, 1) if questions else 0

        domains.append(
            {
                "id": row["id"],
                "number": row["domain_number"],
                "name": row["name"],
                "weight": row["weight"],
                "questions_answered": questions,
                "questions_correct": correct,
                "accuracy": accuracy,
                "color_status": calculate_color_status(accuracy, questions),
                "readiness_status": calculate_readiness_status(
                    certification, accuracy, questions
                ),
                "sample_target": target,
                "evidence_percent": min(
                    round((questions / target) * 100, 1), 100
                ),
                "weakness_score": (
                    round((100 - accuracy) * (row["weight"] / 100), 2)
                    if questions
                    else 999
                ),
            }
        )

    return domains


def get_mock_stats(connection, certification):
    rows = connection.execute(
        """
        SELECT id, questions_answered, questions_correct,
               minutes_spent, assessment_date
        FROM assessments
        WHERE certification = ?
          AND assessment_type = 'mock'
        ORDER BY assessment_date DESC, id DESC
        LIMIT 3
        """,
        (certification,),
    ).fetchall()

    results = []
    for row in rows:
        questions = row["questions_answered"]
        correct = row["questions_correct"]
        accuracy = round(correct / questions * 100, 1) if questions else 0
        results.append(
            {
                "id": row["id"],
                "accuracy": accuracy,
                "questions": questions,
                "correct": correct,
                "minutes": row["minutes_spent"],
                "date": row["assessment_date"],
            }
        )

    average = (
        round(sum(result["accuracy"] for result in results) / len(results), 1)
        if results
        else None
    )

    return {"count": len(results), "average": average, "results": results}


def calculate_overall_readiness(
    certification, domains, mock_stats, open_topic_count
):
    tested = [d for d in domains if d["questions_answered"] > 0]

    if not tested:
        return {
            "score": 0,
            "decision": "NO-GO",
            "reason": "No current domain baseline data yet.",
            "green_count": 0,
            "ready_count": 0,
            "red_count": 0,
            "total_questions": 0,
            "mock_average": mock_stats["average"],
        }

    weighted_domain_score = round(
        sum(d["accuracy"] * (d["weight"] / 100) for d in domains), 1
    )
    green_count = sum(1 for d in domains if d["color_status"] == "GREEN")
    ready_count = sum(1 for d in domains if d["readiness_status"] == "READY")
    red_count = sum(1 for d in domains if d["color_status"] == "RED")
    total_questions = sum(d["questions_answered"] for d in domains)

    if mock_stats["average"] is not None:
        score = round(
            weighted_domain_score * 0.70 + mock_stats["average"] * 0.30,
            1,
        )
    else:
        score = weighted_domain_score

    config = CERTIFICATION_CONFIG[certification]
    all_tested = len(tested) == config["domain_count"]
    required_total = config["sample_target"] * config["domain_count"]

    if (
        all_tested
        and ready_count == config["domain_count"]
        and total_questions >= required_total
        and mock_stats["count"] >= 2
        and mock_stats["average"] is not None
        and mock_stats["average"] >= config["mock_target"]
        and open_topic_count <= 3
    ):
        decision = "GO"
        reason = "Domain evidence, mock performance, and readiness gates are satisfied."
    elif (
        all_tested
        and red_count == 0
        and ready_count >= ceil(config["domain_count"] * 0.75)
        and mock_stats["count"] >= 1
        and mock_stats["average"] is not None
        and mock_stats["average"] >= 75
    ):
        decision = "HOLD"
        reason = "Performance is close. Close remaining readiness gaps before exam day."
    else:
        decision = "NO-GO"
        reason = "Current evidence does not yet support an exam-ready decision."

    return {
        "score": score,
        "decision": decision,
        "reason": reason,
        "green_count": green_count,
        "ready_count": ready_count,
        "red_count": red_count,
        "total_questions": total_questions,
        "mock_average": mock_stats["average"],
    }


def choose_priority_domain(certification, domains, historical_attempt=None):
    """
    Returns the most useful domain to work next.

    Current data always wins once there is enough of it.
    Historical CISM data is only a tie-breaker / bootstrap signal.
    """
    if not domains:
        return None

    # 1. Current RED domains with enough evidence are the strongest signal.
    red = [d for d in domains if d["questions_answered"] >= 20 and d["color_status"] == "RED"]
    if red:
        return max(red, key=lambda d: d["weakness_score"])

    # 2. Current YELLOW domains with enough evidence.
    yellow = [d for d in domains if d["questions_answered"] >= 20 and d["color_status"] == "YELLOW"]
    if yellow:
        return max(yellow, key=lambda d: d["weakness_score"])

    # 3. Thin CISM evidence: use historical weighted gap to decide what to validate first.
    if certification == "CISM" and historical_attempt:
        thin_ids = {
            d["id"]
            for d in domains
            if d["questions_answered"] < 50
        }
        historical_candidates = [
            h for h in historical_attempt["ranked"]
            if h["id"] in thin_ids
        ]
        if historical_candidates:
            chosen_id = historical_candidates[0]["id"]
            return next((d for d in domains if d["id"] == chosen_id), None)

    # 4. Untested / low-evidence domains, highest weight first.
    thin = [
        d for d in domains
        if d["questions_answered"] < d["sample_target"]
    ]
    if thin:
        return max(
            thin,
            key=lambda d: (
                d["weight"],
                -d["questions_answered"],
            ),
        )

    # 5. Everything ready: return weakest accuracy as maintenance target.
    return min(domains, key=lambda d: d["accuracy"])


def build_adaptive_prescription(
    certification,
    phase_code,
    domains,
    readiness,
    mock_stats,
    historical_attempt=None,
):
    target = choose_priority_domain(
        certification,
        domains,
        historical_attempt,
    )

    if not target:
        return {
            "adaptive": False,
            "badge": "NO DATA",
            "headline": "No domain data yet",
            "summary": "Log an assessment to generate a data-driven prescription.",
            "actions": [],
        }

    questions = target["questions_answered"]
    accuracy = target["accuracy"]
    remaining = max(target["sample_target"] - questions, 0)

    if questions == 0:
        summary = (
            f"Start with {target['name']}. It has no current baseline yet."
        )
        actions = [
            f"Run a fresh {certification} question set for {target['name']}.",
            "Do not study the domain first; measure it first.",
            "Review every miss before remediation.",
        ]
    elif target["color_status"] == "RED":
        summary = (
            f"{target['name']} is the primary current weakness at "
            f"{accuracy}% across {questions} questions."
        )
        actions = [
            "Review every miss from the most recent set.",
            "Remediate only the concepts that actually failed.",
            "Retest with unseen questions.",
        ]
    elif target["color_status"] == "YELLOW":
        summary = (
            f"{target['name']} is close but still below the 80% target: "
            f"{accuracy}% across {questions} questions."
        )
        actions = [
            "Run another unseen question set.",
            "Review all misses and interpretation errors.",
            "Use targeted remediation only if the same concepts repeat.",
        ]
    elif remaining > 0:
        summary = (
            f"{target['name']} is currently green at {accuracy}%, but the "
            f"sample is still thin: {questions}/{target['sample_target']}."
        )
        actions = [
            f"Build another {remaining} questions of evidence over multiple sessions.",
            "Keep using unseen questions.",
            "Do not over-study a green domain just to chase a perfect score.",
        ]
    else:
        summary = (
            f"{target['name']} is ready. The priority shifts to mixed validation "
            f"and mock performance."
        )
        actions = [
            "Run mixed-domain assessments.",
            "Use domain-only work only when a new weakness appears.",
            "Protect recent mock performance at or above 80%.",
        ]

    if certification == "CISM" and historical_attempt and questions < 50:
        historical = next(
            (h for h in historical_attempt["domains"] if h["id"] == target["id"]),
            None,
        )
        if historical:
            summary += (
                f" February exam baseline for this domain was "
                f"{historical['score']} scaled."
            )

    if phase_code in {"CISM_FINAL", "CISSP_MOCK"}:
        actions = [
            "Use mixed sets / mocks as the primary evidence source.",
            "Remediate only recurring misses.",
            "Do not reopen full books or courses.",
        ]

    return {
        "adaptive": True,
        "badge": "DATA DRIVEN",
        "headline": target["name"],
        "summary": summary,
        "actions": actions,
        "domain_id": target["id"],
        "accuracy": accuracy,
        "questions": questions,
        "sample_target": target["sample_target"],
        "remaining": remaining,
        "readiness_status": target["readiness_status"],
        "color_status": target["color_status"],
    }


def determine_next_action(certification, domains, historical_attempt=None):
    prescription = build_adaptive_prescription(
        certification,
        "GENERIC",
        domains,
        {
            "score": 0,
            "decision": "NO-GO",
        },
        {
            "average": None,
            "count": 0,
        },
        historical_attempt,
    )

    return {
        "priority": (
            "VALIDATE / REMEDIATE"
            if prescription["adaptive"]
            else "ESTABLISH BASELINE"
        ),
        "title": prescription["headline"],
        "instruction": prescription["summary"],
    }


def build_campaign(
    settings,
    cism_domains,
    cissp_domains,
    cism_readiness,
    cissp_readiness,
    cism_mock_stats,
    cissp_mock_stats,
    cism_historical_attempt,
):
    today = date.today()
    cism_date = parse_date(settings.get("cism_exam_date", ""))
    cissp_date = parse_date(settings.get("cissp_exam_date", ""))

    if not cism_date:
        cism_date = today + timedelta(days=40)

    cism_days = (cism_date - today).days
    intensive_start = cism_date - timedelta(days=21)
    final_start = cism_date - timedelta(days=6)
    transition_end = cism_date + timedelta(days=7)
    domain_build_end = cism_date + timedelta(days=49)
    validation_end = cism_date + timedelta(days=84)

    if cism_days > 21:
        phase_code = "CISM_PRIMARY"
        priority_cert = "CISM"
    elif cism_days >= 7:
        phase_code = "CISM_INTENSIVE"
        priority_cert = "CISM"
    elif cism_days >= 0:
        phase_code = "CISM_FINAL"
        priority_cert = "CISM"
    else:
        days_after_cism = abs(cism_days)
        priority_cert = "CISSP"
        if days_after_cism <= 7:
            phase_code = "CISSP_TRANSITION"
        elif days_after_cism <= 49:
            phase_code = "CISSP_BUILD"
        elif days_after_cism <= 84:
            phase_code = "CISSP_VALIDATION"
        else:
            phase_code = "CISSP_MOCK"

    if (
        cissp_date
        and today > cism_date
        and 0 <= (cissp_date - today).days <= 21
    ):
        phase_code = "CISSP_MOCK"
        priority_cert = "CISSP"

    phase_data = {
        "CISM_PRIMARY": {
            "title": "CISM Primary",
            "dates": f"Now → {format_date(intensive_start - timedelta(days=1))}",
            "work": "Validate February weaknesses and build current evidence.",
            "objective": "Build current CISM evidence without wasting time rereading material you already know.",
            "study_items": [
                "Pocket Prep is the primary engine.",
                "Review every miss.",
                "Use Chapple only for demonstrated gaps.",
                "Use YouTube only if the concept still does not click.",
                "Keep CISSP in maintenance mode.",
            ],
            "targets": [
                "At least 50 current questions per CISM domain.",
                "Move every domain toward 80%+.",
                "Confirm or disprove the February weaknesses.",
            ],
            "resources": "Pocket Prep → Chapple CISM Study Guide → YouTube.",
            "exit": "All four CISM domains have meaningful current evidence.",
        },
        "CISM_INTENSIVE": {
            "title": "CISM Intensive",
            "dates": f"{format_date(intensive_start)} → {format_date(final_start - timedelta(days=1))}",
            "work": "Question-driven CISM remediation.",
            "objective": "Turn known weaknesses into stable mixed-question performance.",
            "study_items": [
                "Run 30–50 question mixed sets.",
                "Attack the lowest-performing weighted domain first.",
                "Review every miss before adding more questions.",
                "Use Chapple and YouTube only for targeted remediation.",
            ],
            "targets": [
                "80%+ on fresh mixed sets.",
                "Build toward 100 questions per CISM domain.",
                "No domain consistently below 70%.",
            ],
            "resources": "Pocket Prep → Chapple CISM Study Guide → YouTube.",
            "exit": "No major red domain and mixed scores are stable.",
        },
        "CISM_FINAL": {
            "title": "CISM Final",
            "dates": f"{format_date(final_start)} → {format_date(cism_date)}",
            "work": "Final review and exam execution.",
            "objective": "Protect decision quality and avoid destabilizing preparation.",
            "study_items": [
                "Mixed Pocket Prep only.",
                "Review recurring misses and weak topics.",
                "No broad rereading.",
                "No new resources.",
            ],
            "targets": [
                "Recent mixed performance around or above 80%.",
                "No unresolved major weakness.",
                "Protect sleep and exam execution.",
            ],
            "resources": "Pocket Prep + targeted Chapple review.",
            "exit": "Sit the CISM exam.",
        },
        "CISSP_TRANSITION": {
            "title": "CISSP Transition",
            "dates": f"{format_date(cism_date + timedelta(days=1))} → {format_date(transition_end)}",
            "work": "Baseline and restart CISSP curriculum.",
            "objective": "Switch mental models from CISM to CISSP and identify the real gaps.",
            "study_items": [
                "Resume ISC2 self-paced.",
                "Run baseline Pocket Prep across all eight domains.",
                "Use Chapple only when the baseline exposes a specific weakness.",
            ],
            "targets": [
                "Every CISSP domain has baseline data.",
                "Identify red, yellow, and green domains.",
            ],
            "resources": "ISC2 Self-Paced → Pocket Prep → Chapple → 7th Edition / targeted video.",
            "exit": "All 8 domains have baseline data.",
        },
        "CISSP_BUILD": {
            "title": "CISSP Domain Build",
            "dates": f"{format_date(transition_end + timedelta(days=1))} → {format_date(domain_build_end)}",
            "work": "ISC2 → Pocket Prep → Chapple → retest.",
            "objective": "Build competence and enough evidence to trust the percentages.",
            "study_items": [
                "Use Next Action to choose the priority domain.",
                "Complete relevant ISC2 material.",
                "Run 25–40 Pocket Prep questions.",
                "Review every miss.",
                "Retest with unseen questions.",
            ],
            "targets": [
                "80%+ accuracy target.",
                "Build toward 150 questions per domain.",
                "No red domain without active remediation.",
            ],
            "resources": "ISC2 Self-Paced → Pocket Prep → Chapple → 7th Edition / targeted video.",
            "exit": "Most domains are green or approaching green.",
        },
        "CISSP_VALIDATION": {
            "title": "CISSP Validation",
            "dates": f"{format_date(domain_build_end + timedelta(days=1))} → {format_date(validation_end)}",
            "work": "150/domain target and mixed testing.",
            "objective": "Prove that domain knowledge survives mixed testing.",
            "study_items": [
                "Shift most question work to mixed sets.",
                "Use domain-only sets for yellow/red areas.",
                "Begin Mock Readiness Exams.",
                "Do not restart entire courses or books.",
            ],
            "targets": [
                "150 questions per domain.",
                "80%+ cumulative accuracy in each domain.",
                "At least one serious mock readiness exam.",
                "No red domains.",
            ],
            "resources": "Pocket Prep dominant; ISC2/Chapple become remediation references.",
            "exit": "Mock performance becomes the main readiness signal.",
        },
        "CISSP_MOCK": {
            "title": "CISSP Mock Readiness",
            "dates": f"{format_date(validation_end + timedelta(days=1))} → Exam",
            "work": "Mock exams and targeted cleanup.",
            "objective": "Validate exam-level performance without relearning material you already know.",
            "study_items": [
                "Run full mixed mock exams.",
                "Analyze miss patterns after every mock.",
                "Remediate recurring topics only.",
                "Do not add new resources.",
            ],
            "targets": [
                "At least two serious mock exams.",
                "Recent mock average at or above 80%.",
                "All 8 domains at or above 80% with strong evidence.",
            ],
            "resources": "Pocket Prep / mock source → targeted Chapple or ISC2 remediation.",
            "exit": "Dashboard reaches GO and recent performance supports sitting the CISSP.",
        },
    }

    ordered_codes = [
        "CISM_PRIMARY",
        "CISM_INTENSIVE",
        "CISM_FINAL",
        "CISSP_TRANSITION",
        "CISSP_BUILD",
        "CISSP_VALIDATION",
        "CISSP_MOCK",
    ]

    current_index = ordered_codes.index(phase_code)

    phases = []
    for index, code in enumerate(ordered_codes):
        item = dict(phase_data[code])
        item["code"] = code
        item["status"] = (
            "COMPLETE"
            if index < current_index
            else "CURRENT"
            if index == current_index
            else "UPCOMING"
        )

        if code.startswith("CISM"):
            item["adaptive_prescription"] = build_adaptive_prescription(
                "CISM",
                code,
                cism_domains,
                cism_readiness,
                cism_mock_stats,
                cism_historical_attempt,
            )
        else:
            item["adaptive_prescription"] = build_adaptive_prescription(
                "CISSP",
                code,
                cissp_domains,
                cissp_readiness,
                cissp_mock_stats,
                None,
            )

        phases.append(item)

    active_phase = next(p for p in phases if p["code"] == phase_code)
    adaptive = active_phase["adaptive_prescription"]

    banner = {
        "certification": priority_cert,
        "phase": active_phase["title"].upper(),
        "headline": f"YOU SHOULD BE STUDYING {priority_cert}",
        "prescription": (
            f"{adaptive['headline']}: {adaptive['summary']}"
            if adaptive["adaptive"]
            else active_phase["work"]
        ),
        "data_driven": adaptive["adaptive"],
    }

    return {
        "banner": banner,
        "phases": phases,
        "phase_code": phase_code,
    }


@app.route("/")
def dashboard():
    active_cert = get_active_certification()
    connection = get_db_connection()
    settings = get_settings(connection)

    # Build both certifications every time so campaign guidance is
    # independent of whichever dashboard the user happens to be viewing.
    cism_domains = build_domains(connection, "CISM")
    cissp_domains = build_domains(connection, "CISSP")

    cism_historical_attempt = get_historical_attempt(connection, "CISM")
    active_historical_attempt = (
        cism_historical_attempt if active_cert == "CISM" else None
    )

    active_domains = cism_domains if active_cert == "CISM" else cissp_domains

    open_topics = connection.execute(
        """
        SELECT w.id, w.domain_id, w.topic, d.domain_number,
               d.name AS domain_name
        FROM weak_topics w
        JOIN domains d ON d.id = w.domain_id
        WHERE w.status = 'OPEN'
          AND w.certification = ?
        ORDER BY w.created_at DESC
        """,
        (active_cert,),
    ).fetchall()

    recent_assessments = connection.execute(
        """
        SELECT a.id, a.assessment_type, a.source,
               a.questions_answered, a.questions_correct,
               a.minutes_spent, a.assessment_date,
               d.name AS domain_name
        FROM assessments a
        LEFT JOIN domains d ON d.id = a.domain_id
        WHERE a.certification = ?
        ORDER BY a.assessment_date DESC, a.id DESC
        LIMIT 8
        """,
        (active_cert,),
    ).fetchall()

    recent_study = connection.execute(
        """
        SELECT s.id, s.resource, s.minutes_studied,
               s.session_date, d.name AS domain_name
        FROM study_sessions s
        LEFT JOIN domains d ON d.id = s.domain_id
        WHERE s.certification = ?
        ORDER BY s.session_date DESC, s.id DESC
        LIMIT 8
        """,
        (active_cert,),
    ).fetchall()

    total_study_row = connection.execute(
        """
        SELECT COALESCE(SUM(minutes_studied), 0) AS minutes
        FROM study_sessions
        WHERE certification = ?
        """,
        (active_cert,),
    ).fetchone()

    total_assessment_row = connection.execute(
        """
        SELECT COALESCE(SUM(minutes_spent), 0) AS minutes
        FROM assessments
        WHERE certification = ?
        """,
        (active_cert,),
    ).fetchone()

    cism_open_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM weak_topics
        WHERE status = 'OPEN'
          AND certification = 'CISM'
        """
    ).fetchone()["count"]

    cissp_open_count = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM weak_topics
        WHERE status = 'OPEN'
          AND certification = 'CISSP'
        """
    ).fetchone()["count"]

    cism_mock_stats = get_mock_stats(connection, "CISM")
    cissp_mock_stats = get_mock_stats(connection, "CISSP")

    connection.close()

    cism_readiness = calculate_overall_readiness(
        "CISM",
        cism_domains,
        cism_mock_stats,
        cism_open_count,
    )
    cissp_readiness = calculate_overall_readiness(
        "CISSP",
        cissp_domains,
        cissp_mock_stats,
        cissp_open_count,
    )

    active_readiness = (
        cism_readiness if active_cert == "CISM" else cissp_readiness
    )
    active_mock_stats = (
        cism_mock_stats if active_cert == "CISM" else cissp_mock_stats
    )

    total_questions = sum(d["questions_answered"] for d in active_domains)
    total_correct = sum(d["questions_correct"] for d in active_domains)
    overall_accuracy = (
        round(total_correct / total_questions * 100, 1)
        if total_questions
        else 0
    )

    total_minutes = total_study_row["minutes"] + total_assessment_row["minutes"]

    next_action = determine_next_action(
        active_cert,
        active_domains,
        active_historical_attempt,
    )

    campaign = build_campaign(
        settings,
        cism_domains,
        cissp_domains,
        cism_readiness,
        cissp_readiness,
        cism_mock_stats,
        cissp_mock_stats,
        cism_historical_attempt,
    )

    return render_template(
        "index.html",
        active_cert=active_cert,
        config=CERTIFICATION_CONFIG[active_cert],
        domains=active_domains,
        settings=settings,
        open_topics=open_topics,
        recent_assessments=recent_assessments,
        recent_study=recent_study,
        mock_stats=active_mock_stats,
        historical_attempt=active_historical_attempt,
        total_questions=total_questions,
        overall_accuracy=overall_accuracy,
        total_hours=round(total_minutes / 60, 1),
        readiness=active_readiness,
        next_action=next_action,
        campaign=campaign,
        cism_days=days_until(settings.get("cism_exam_date", "")),
        cissp_days=days_until(settings.get("cissp_exam_date", "")),
    )


@app.route("/log-assessment", methods=["POST"])
def log_assessment():
    certification = request.form["certification"].upper()
    if certification not in VALID_CERTIFICATIONS:
        certification = "CISSP"

    assessment_type = request.form["assessment_type"]
    source = request.form["source"].strip()

    try:
        questions = int(request.form["questions"])
        correct = int(request.form["correct"])
        minutes = int(request.form.get("minutes", 0) or 0)
        knowledge = int(request.form.get("knowledge_misses", 0) or 0)
        interpretation = int(request.form.get("interpretation_misses", 0) or 0)
        mindset = int(request.form.get("mindset_misses", 0) or 0)
    except ValueError:
        flash("Assessment contains invalid numbers.", "error")
        return redirect(url_for("dashboard", cert=certification))

    if questions <= 0 or correct < 0 or correct > questions or minutes < 0:
        flash("Assessment totals are invalid.", "error")
        return redirect(url_for("dashboard", cert=certification))

    misses = questions - correct
    if (
        knowledge < 0
        or interpretation < 0
        or mindset < 0
        or knowledge + interpretation + mindset > misses
    ):
        flash(
            "Miss classifications cannot exceed total missed questions.",
            "error",
        )
        return redirect(url_for("dashboard", cert=certification))

    notes = request.form.get("notes", "").strip()
    domain_id = request.form.get("domain_id")

    if assessment_type != "single":
        domain_id = None
    elif domain_id:
        domain_id = int(domain_id)

    connection = get_db_connection()

    cursor = connection.execute(
        """
        INSERT INTO assessments (
            certification, assessment_type, source, domain_id,
            questions_answered, questions_correct,
            knowledge_misses, interpretation_misses, mindset_misses,
            minutes_spent, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            certification,
            assessment_type,
            source,
            domain_id,
            questions,
            correct,
            knowledge,
            interpretation,
            mindset,
            minutes,
            notes,
        ),
    )

    assessment_id = cursor.lastrowid

    if assessment_type == "single" and domain_id:
        connection.execute(
            """
            UPDATE domains
            SET questions_answered = questions_answered + ?,
                questions_correct = questions_correct + ?
            WHERE id = ?
              AND certification = ?
            """,
            (questions, correct, domain_id, certification),
        )

    if assessment_type == "mixed":
        domain_rows = connection.execute(
            """
            SELECT id, domain_number
            FROM domains
            WHERE certification = ?
            ORDER BY domain_number
            """,
            (certification,),
        ).fetchall()

        breakdown = []
        for domain in domain_rows:
            number = domain["domain_number"]
            q_value = request.form.get(f"domain_{number}_questions", "")
            c_value = request.form.get(f"domain_{number}_correct", "")

            if not q_value:
                continue

            try:
                domain_questions = int(q_value)
                domain_correct = int(c_value or 0)
            except ValueError:
                continue

            if domain_questions <= 0:
                continue
            if domain_correct < 0 or domain_correct > domain_questions:
                continue

            breakdown.append(
                (domain["id"], domain_questions, domain_correct)
            )

        if breakdown:
            breakdown_questions = sum(item[1] for item in breakdown)
            breakdown_correct = sum(item[2] for item in breakdown)

            if (
                breakdown_questions != questions
                or breakdown_correct != correct
            ):
                connection.rollback()
                connection.close()
                flash(
                    "Mixed-domain breakdown does not match the overall Correct / Answered totals.",
                    "error",
                )
                return redirect(url_for("dashboard", cert=certification))

            for breakdown_domain_id, domain_questions, domain_correct in breakdown:
                connection.execute(
                    """
                    INSERT INTO assessment_domain_results (
                        assessment_id, domain_id,
                        questions_answered, questions_correct
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        assessment_id,
                        breakdown_domain_id,
                        domain_questions,
                        domain_correct,
                    ),
                )
                connection.execute(
                    """
                    UPDATE domains
                    SET questions_answered = questions_answered + ?,
                        questions_correct = questions_correct + ?
                    WHERE id = ?
                    """,
                    (
                        domain_questions,
                        domain_correct,
                        breakdown_domain_id,
                    ),
                )

    connection.commit()
    connection.close()

    flash("Assessment logged.", "success")
    return redirect(url_for("dashboard", cert=certification))


@app.route("/log-study", methods=["POST"])
def log_study():
    certification = request.form["certification"].upper()
    domain_id = request.form.get("study_domain_id")
    domain_id = int(domain_id) if domain_id else None
    resource = request.form["study_resource"].strip()

    try:
        minutes = int(request.form["study_minutes"])
    except ValueError:
        minutes = 0

    notes = request.form.get("study_notes", "").strip()

    if minutes <= 0:
        flash("Study time must be greater than zero.", "error")
        return redirect(url_for("dashboard", cert=certification))

    connection = get_db_connection()
    connection.execute(
        """
        INSERT INTO study_sessions (
            certification, domain_id, resource, minutes_studied, notes
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (certification, domain_id, resource, minutes, notes),
    )
    connection.commit()
    connection.close()

    flash("Study session logged.", "success")
    return redirect(url_for("dashboard", cert=certification))


@app.route("/add-topic", methods=["POST"])
def add_topic():
    certification = request.form["certification"].upper()
    topic = request.form["topic"].strip()
    domain_id = int(request.form["domain_id"])

    if not topic:
        return redirect(url_for("dashboard", cert=certification))

    connection = get_db_connection()
    connection.execute(
        """
        INSERT INTO weak_topics (certification, domain_id, topic)
        VALUES (?, ?, ?)
        """,
        (certification, domain_id, topic),
    )
    connection.commit()
    connection.close()

    return redirect(url_for("dashboard", cert=certification))


@app.route("/resolve-topic/<int:topic_id>", methods=["POST"])
def resolve_topic(topic_id):
    certification = request.form["certification"].upper()
    connection = get_db_connection()
    connection.execute(
        """
        UPDATE weak_topics
        SET status = 'RESOLVED',
            resolved_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (topic_id,),
    )
    connection.commit()
    connection.close()

    return redirect(url_for("dashboard", cert=certification))


@app.route("/settings", methods=["POST"])
def update_settings():
    active_cert = request.form.get("active_cert", "CISSP")
    values = {
        "cism_exam_date": request.form.get("cism_exam_date", ""),
        "cissp_exam_date": request.form.get("cissp_exam_date", ""),
        "weekly_hour_target": request.form.get("weekly_hour_target", "10"),
    }

    connection = get_db_connection()
    for key, value in values.items():
        connection.execute(
            """
            INSERT INTO settings (key, value)
            VALUES (?, ?)
            ON CONFLICT(key)
            DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
    connection.commit()
    connection.close()

    flash("Campaign settings updated.", "success")
    return redirect(url_for("dashboard", cert=active_cert))


if __name__ == "__main__":
    initialize_database()
    app.run(debug=True, port=5001)

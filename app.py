from datetime import date, datetime

from flask import Flask, render_template, request, redirect, url_for

from database import get_db_connection, initialize_database


app = Flask(__name__)


RESOURCE_ORDER = {
    "ISC2 Self-Paced": 1,
    "Pocket Prep": 2,
    "Chapple Study Guide": 3,
    "7th Edition Reference": 4,
    "Targeted Video": 5,
}


def get_settings(connection):
    rows = connection.execute(
        "SELECT key, value FROM settings"
    ).fetchall()

    return {row["key"]: row["value"] for row in rows}


def days_until(date_string):
    if not date_string:
        return None

    try:
        target = datetime.strptime(date_string, "%Y-%m-%d").date()
        return (target - date.today()).days
    except ValueError:
        return None


def calculate_status(accuracy, questions):
    """
    Conservative readiness thresholds.

    UNTESTED:
        No data.

    RED:
        <70% or fewer than 50 questions.

    YELLOW:
        70-79.9%, or good accuracy without enough volume.

    GREEN:
        >=80% with at least 100 questions.
    """

    if questions == 0:
        return "UNTESTED"

    if accuracy < 70:
        return "RED"

    if questions < 50:
        return "RED"

    if accuracy < 80:
        return "YELLOW"

    if questions < 100:
        return "YELLOW"

    return "GREEN"


def build_domains(connection):
    rows = connection.execute(
        """
        SELECT
            d.id,
            d.name,
            d.weight,
            d.questions_answered,
            d.questions_correct,

            COALESCE(SUM(s.knowledge_misses), 0)
                AS knowledge_misses,

            COALESCE(SUM(s.interpretation_misses), 0)
                AS interpretation_misses,

            COALESCE(SUM(s.mindset_misses), 0)
                AS mindset_misses,

            COALESCE(SUM(s.minutes_studied), 0)
                AS minutes_studied

        FROM domains d

        LEFT JOIN study_sessions s
            ON s.domain_id = d.id

        GROUP BY d.id

        ORDER BY d.id
        """
    ).fetchall()

    domains = []

    for row in rows:
        questions = row["questions_answered"]
        correct = row["questions_correct"]

        accuracy = (
            round((correct / questions) * 100, 1)
            if questions
            else 0
        )

        status = calculate_status(accuracy, questions)

        miss_types = {
            "Knowledge": row["knowledge_misses"],
            "Interpretation": row["interpretation_misses"],
            "CISSP Mindset": row["mindset_misses"],
        }

        dominant_miss = None

        if sum(miss_types.values()) > 0:
            dominant_miss = max(
                miss_types,
                key=miss_types.get,
            )

        # Weakness score:
        # lower accuracy + higher exam weight = higher priority.
        if questions:
            weakness_score = round(
                (100 - accuracy) * (row["weight"] / 100),
                2,
            )
        else:
            weakness_score = 999

        domains.append(
            {
                "id": row["id"],
                "name": row["name"],
                "weight": row["weight"],
                "questions_answered": questions,
                "questions_correct": correct,
                "accuracy": accuracy,
                "status": status,
                "knowledge_misses": row["knowledge_misses"],
                "interpretation_misses": row["interpretation_misses"],
                "mindset_misses": row["mindset_misses"],
                "dominant_miss": dominant_miss,
                "minutes_studied": row["minutes_studied"],
                "weakness_score": weakness_score,
            }
        )

    return domains


def determine_next_action(domains, settings, open_topics):
    phase = settings.get("phase", "CISM")

    cism_days = days_until(
        settings.get("cism_exam_date", "")
    )

    # CISM protection mode.
    if (
        phase == "CISM"
        and cism_days is not None
        and cism_days >= 0
    ):
        return {
            "priority": "CISM PRIMARY",
            "title": "Protect the CISM Exam",
            "instruction": (
                "CISM remains the primary certification until exam day. "
                "Keep CISSP work controlled: 20-30 mixed questions or one "
                "short ISC2 lesson per session. Do not launch a full CISSP "
                "sprint yet."
            ),
        }

    untested = [
        domain
        for domain in domains
        if domain["questions_answered"] == 0
    ]

    if untested:
        domain = max(
            untested,
            key=lambda item: item["weight"],
        )

        return {
            "priority": "BASELINE",
            "title": (
                f'Domain {domain["id"]}: '
                f'{domain["name"]}'
            ),
            "instruction": (
                "Establish a baseline. Complete 30-50 unseen questions. "
                "Do not remediate before the first set; measure the weakness "
                "before treating it."
            ),
        }

    weak_domains = [
        domain
        for domain in domains
        if domain["status"] != "GREEN"
    ]

    if weak_domains:
        domain = max(
            weak_domains,
            key=lambda item: item["weakness_score"],
        )

        if domain["accuracy"] < 70:
            instruction = (
                "Remediation required. Use the ISC2 self-paced material "
                "for this domain, then Chapple only for the specific concepts "
                "you missed. Finish with 30 new Pocket Prep questions."
            )

        elif domain["accuracy"] < 80:
            instruction = (
                "Question-driven remediation. Complete 30 new questions, "
                "review every miss, and use Chapple only for concepts that "
                "remain unclear."
            )

        else:
            instruction = (
                "Accuracy is acceptable but evidence is thin. Build question "
                "volume to at least 100 without allowing accuracy to fall "
                "below 80%."
            )

        return {
            "priority": "CISSP REMEDIATION",
            "title": (
                f'Domain {domain["id"]}: '
                f'{domain["name"]}'
            ),
            "instruction": instruction,
        }

    if open_topics:
        topic = open_topics[0]

        return {
            "priority": "CLOSE WEAKNESS",
            "title": topic["topic"],
            "instruction": (
                "All domains meet the readiness floor. Close this remaining "
                "weak topic, then validate it with unseen questions."
            ),
        }

    return {
        "priority": "EXAM MODE",
        "title": "Mixed-Domain Validation",
        "instruction": (
            "Stop domain-by-domain studying. Run mixed unseen question sets "
            "under time pressure. Review misses only. Protect your 80%+ "
            "performance across all eight domains."
        ),
    }


def calculate_readiness(domains, open_topic_count):
    tested = [
        d for d in domains
        if d["questions_answered"] > 0
    ]

    if not tested:
        return {
            "score": 0,
            "decision": "NO-GO",
            "reason": "No baseline data.",
        }

    weighted_score = sum(
        d["accuracy"] * (d["weight"] / 100)
        for d in domains
    )

    green_count = sum(
        1 for d in domains
        if d["status"] == "GREEN"
    )

    red_count = sum(
        1 for d in domains
        if d["status"] == "RED"
    )

    total_questions = sum(
        d["questions_answered"]
        for d in domains
    )

    all_tested = len(tested) == 8

    readiness_score = round(weighted_score, 1)

    if (
        all_tested
        and green_count == 8
        and total_questions >= 1000
        and open_topic_count <= 3
        and readiness_score >= 80
    ):
        decision = "GO"
        reason = "Readiness gates satisfied."

    elif (
        all_tested
        and red_count == 0
        and total_questions >= 600
        and readiness_score >= 77
    ):
        decision = "HOLD"
        reason = (
            "Close yellow domains and increase validated question volume."
        )

    else:
        decision = "NO-GO"
        reason = (
            "Readiness evidence is not strong enough yet."
        )

    return {
        "score": readiness_score,
        "decision": decision,
        "reason": reason,
        "green_count": green_count,
        "red_count": red_count,
        "total_questions": total_questions,
    }


@app.route("/")
def dashboard():
    connection = get_db_connection()

    settings = get_settings(connection)
    domains = build_domains(connection)

    open_topics = connection.execute(
        """
        SELECT
            w.id,
            w.topic,
            w.domain_id,
            d.name AS domain_name
        FROM weak_topics w
        JOIN domains d
            ON d.id = w.domain_id
        WHERE w.status = 'OPEN'
        ORDER BY w.created_at DESC
        """
    ).fetchall()

    recent_sessions = connection.execute(
        """
        SELECT
            s.id,
            s.session_date,
            s.questions_answered,
            s.questions_correct,
            s.minutes_studied,
            s.resource,
            d.id AS domain_id,
            d.name AS domain_name
        FROM study_sessions s
        JOIN domains d
            ON d.id = s.domain_id
        ORDER BY s.session_date DESC, s.id DESC
        LIMIT 8
        """
    ).fetchall()

    connection.close()

    total_questions = sum(
        d["questions_answered"]
        for d in domains
    )

    total_correct = sum(
        d["questions_correct"]
        for d in domains
    )

    overall_accuracy = (
        round((total_correct / total_questions) * 100, 1)
        if total_questions
        else 0
    )

    total_minutes = sum(
        d["minutes_studied"]
        for d in domains
    )

    total_hours = round(total_minutes / 60, 1)

    next_action = determine_next_action(
        domains,
        settings,
        open_topics,
    )

    readiness = calculate_readiness(
        domains,
        len(open_topics),
    )

    return render_template(
        "index.html",
        domains=domains,
        settings=settings,
        open_topics=open_topics,
        recent_sessions=recent_sessions,
        total_questions=total_questions,
        overall_accuracy=overall_accuracy,
        total_hours=total_hours,
        next_action=next_action,
        readiness=readiness,
        cism_days=days_until(
            settings.get("cism_exam_date", "")
        ),
        cissp_days=days_until(
            settings.get("cissp_exam_date", "")
        ),
    )


@app.route("/log-session", methods=["POST"])
def log_session():
    domain_id = int(request.form["domain_id"])
    questions = int(request.form.get("questions", 0))
    correct = int(request.form.get("correct", 0))
    minutes = int(request.form.get("minutes", 0))

    knowledge = int(
        request.form.get("knowledge_misses", 0)
    )

    interpretation = int(
        request.form.get("interpretation_misses", 0)
    )

    mindset = int(
        request.form.get("mindset_misses", 0)
    )

    resource = request.form.get("resource", "").strip()
    notes = request.form.get("notes", "").strip()

    misses = questions - correct

    if (
        questions < 0
        or correct < 0
        or correct > questions
        or minutes < 0
        or knowledge < 0
        or interpretation < 0
        or mindset < 0
    ):
        return redirect(url_for("dashboard"))

    if (
        questions > 0
        and knowledge + interpretation + mindset > misses
    ):
        return redirect(url_for("dashboard"))

    connection = get_db_connection()

    connection.execute(
        """
        INSERT INTO study_sessions (
            domain_id,
            questions_answered,
            questions_correct,
            knowledge_misses,
            interpretation_misses,
            mindset_misses,
            minutes_studied,
            resource,
            notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            domain_id,
            questions,
            correct,
            knowledge,
            interpretation,
            mindset,
            minutes,
            resource,
            notes,
        ),
    )

    connection.execute(
        """
        UPDATE domains
        SET
            questions_answered =
                questions_answered + ?,
            questions_correct =
                questions_correct + ?
        WHERE id = ?
        """,
        (
            questions,
            correct,
            domain_id,
        ),
    )

    connection.commit()
    connection.close()

    return redirect(url_for("dashboard"))


@app.route("/add-topic", methods=["POST"])
def add_topic():
    domain_id = int(request.form["domain_id"])
    topic = request.form["topic"].strip()

    if not topic:
        return redirect(url_for("dashboard"))

    connection = get_db_connection()

    connection.execute(
        """
        INSERT INTO weak_topics (
            domain_id,
            topic
        )
        VALUES (?, ?)
        """,
        (domain_id, topic),
    )

    connection.commit()
    connection.close()

    return redirect(url_for("dashboard"))


@app.route("/resolve-topic/<int:topic_id>", methods=["POST"])
def resolve_topic(topic_id):
    connection = get_db_connection()

    connection.execute(
        """
        UPDATE weak_topics
        SET
            status = 'RESOLVED',
            resolved_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (topic_id,),
    )

    connection.commit()
    connection.close()

    return redirect(url_for("dashboard"))


@app.route("/settings", methods=["POST"])
def update_settings():
    values = {
        "cism_exam_date":
            request.form.get("cism_exam_date", ""),

        "cissp_exam_date":
            request.form.get("cissp_exam_date", ""),

        "phase":
            request.form.get("phase", "CISM"),

        "weekly_hour_target":
            request.form.get(
                "weekly_hour_target",
                "10",
            ),
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

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    initialize_database()
    app.run(
        debug=True,
        port=5001,
    )
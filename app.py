from datetime import date, datetime, timedelta
from functools import wraps
from math import ceil
import os

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from database import (
    get_db_connection,
    initialize_database,
)


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "certification-command-center-local-dev",
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(
        os.environ.get(
            "RENDER_EXTERNAL_HOSTNAME"
        )
    ),
)

VALID_CERTIFICATIONS = {
    "CISSP",
    "CISM",
}

MAX_ACTIVE_USERS = 3

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


# ============================================================
# AUTHENTICATION
# ============================================================

def current_user():
    user_id = session.get(
        "user_id"
    )

    if not user_id:
        return None

    connection = get_db_connection()

    user = connection.execute(
        """
        SELECT
            id,
            username,
            display_name,
            is_admin,
            is_active
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()

    connection.close()

    if not user:
        session.clear()
        return None

    if not user["is_active"]:
        session.clear()
        return None

    return user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()

        if not user:
            return redirect(
                url_for(
                    "login",
                    next=request.full_path
                    if request.query_string
                    else request.path,
                )
            )

        return view(
            *args,
            **kwargs,
        )

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()

        if not user:
            return redirect(
                url_for("login")
            )

        if not user["is_admin"]:
            abort(403)

        return view(
            *args,
            **kwargs,
        )

    return wrapped


@app.route(
    "/login",
    methods=[
        "GET",
        "POST",
    ],
)
def login():
    if current_user():
        return redirect(
            url_for("dashboard")
        )

    error = None

    if request.method == "POST":
        username = request.form.get(
            "username",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        connection = get_db_connection()

        user = connection.execute(
            """
            SELECT
                id,
                username,
                display_name,
                password_hash,
                is_admin,
                is_active
            FROM users
            WHERE username = ?
            COLLATE NOCASE
            """,
            (username,),
        ).fetchone()

        connection.close()

        if (
            user
            and user["is_active"]
            and check_password_hash(
                user["password_hash"],
                password,
            )
        ):
            session.clear()

            session[
                "user_id"
            ] = user["id"]

            next_url = request.form.get(
                "next",
                "",
            )

            if (
                next_url
                and next_url.startswith("/")
                and not next_url.startswith("//")
            ):
                return redirect(
                    next_url
                )

            return redirect(
                url_for("dashboard")
            )

        error = (
            "Invalid username or password."
        )

    return render_template(
        "login.html",
        error=error,
        next_url=request.args.get(
            "next",
            "",
        ),
    )


@app.route("/logout")
def logout():
    session.clear()

    return redirect(
        url_for("login")
    )


@app.route("/health")
def health():
    return {
        "status": "ok"
    }, 200


# ============================================================
# ADMIN USER MANAGEMENT
# ============================================================

@app.route(
    "/admin/users",
    methods=[
        "GET",
        "POST",
    ],
)
@admin_required
def admin_users():
    user = current_user()

    connection = get_db_connection()

    if request.method == "POST":
        action = request.form.get(
            "action",
            "",
        )

        if action == "create":
            username = request.form.get(
                "username",
                "",
            ).strip()

            display_name = request.form.get(
                "display_name",
                "",
            ).strip()

            password = request.form.get(
                "password",
                "",
            )

            active_count = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM users
                WHERE is_active = 1
                """
            ).fetchone()["count"]

            if active_count >= MAX_ACTIVE_USERS:
                flash(
                    "This build is capped at 3 active users.",
                    "error",
                )

            elif len(username) < 3:
                flash(
                    "Username must be at least 3 characters.",
                    "error",
                )

            elif len(password) < 10:
                flash(
                    "Temporary password must be at least 10 characters.",
                    "error",
                )

            else:
                existing = connection.execute(
                    """
                    SELECT id
                    FROM users
                    WHERE username = ?
                    COLLATE NOCASE
                    """,
                    (username,),
                ).fetchone()

                if existing:
                    flash(
                        "That username already exists.",
                        "error",
                    )

                else:
                    cursor = connection.execute(
                        """
                        INSERT INTO users (
                            username,
                            display_name,
                            password_hash,
                            is_admin,
                            is_active
                        )
                        VALUES (?, ?, ?, 0, 1)
                        """,
                        (
                            username,
                            display_name or username,
                            generate_password_hash(
                                password
                            ),
                        ),
                    )

                    new_user_id = cursor.lastrowid

                    # Default campaign settings.
                    connection.executemany(
                        """
                        INSERT OR IGNORE INTO user_settings (
                            user_id,
                            key,
                            value
                        )
                        VALUES (?, ?, ?)
                        """,
                        [
                            (
                                new_user_id,
                                "cism_exam_date",
                                "",
                            ),
                            (
                                new_user_id,
                                "cissp_exam_date",
                                "",
                            ),
                            (
                                new_user_id,
                                "weekly_hour_target",
                                "10",
                            ),
                        ],
                    )

                    # Empty personal readiness stats.
                    domain_rows = connection.execute(
                        """
                        SELECT id
                        FROM domains
                        """
                    ).fetchall()

                    connection.executemany(
                        """
                        INSERT OR IGNORE INTO user_domain_stats (
                            user_id,
                            domain_id,
                            questions_answered,
                            questions_correct
                        )
                        VALUES (?, ?, 0, 0)
                        """,
                        [
                            (
                                new_user_id,
                                domain["id"],
                            )
                            for domain in domain_rows
                        ],
                    )

                    flash(
                        f"User {username} created.",
                        "success",
                    )

        elif action == "reset_password":
            target_user_id = int(
                request.form.get(
                    "user_id",
                    0,
                )
            )

            new_password = request.form.get(
                "new_password",
                "",
            )

            if len(new_password) < 10:
                flash(
                    "New password must be at least 10 characters.",
                    "error",
                )

            else:
                connection.execute(
                    """
                    UPDATE users
                    SET password_hash = ?
                    WHERE id = ?
                    """,
                    (
                        generate_password_hash(
                            new_password
                        ),
                        target_user_id,
                    ),
                )

                flash(
                    "Password reset.",
                    "success",
                )

        elif action == "toggle_active":
            target_user_id = int(
                request.form.get(
                    "user_id",
                    0,
                )
            )

            if target_user_id == user["id"]:
                flash(
                    "You cannot disable your own account.",
                    "error",
                )

            else:
                target = connection.execute(
                    """
                    SELECT
                        id,
                        username,
                        is_active
                    FROM users
                    WHERE id = ?
                    """,
                    (target_user_id,),
                ).fetchone()

                if target:
                    new_state = (
                        0
                        if target["is_active"]
                        else 1
                    )

                    if new_state == 1:
                        active_count = connection.execute(
                            """
                            SELECT COUNT(*) AS count
                            FROM users
                            WHERE is_active = 1
                            """
                        ).fetchone()["count"]

                        if active_count >= MAX_ACTIVE_USERS:
                            flash(
                                "Cannot enable another user: 3-user cap reached.",
                                "error",
                            )

                            connection.commit()

                            users = connection.execute(
                                """
                                SELECT
                                    id,
                                    username,
                                    display_name,
                                    is_admin,
                                    is_active,
                                    created_at
                                FROM users
                                ORDER BY is_admin DESC, id
                                """
                            ).fetchall()

                            connection.close()

                            return render_template(
                                "admin_users.html",
                                users=users,
                                current_user=user,
                                max_active_users=MAX_ACTIVE_USERS,
                            )

                    connection.execute(
                        """
                        UPDATE users
                        SET is_active = ?
                        WHERE id = ?
                        """,
                        (
                            new_state,
                            target_user_id,
                        ),
                    )

                    flash(
                        (
                            f"{target['username']} enabled."
                            if new_state
                            else f"{target['username']} disabled."
                        ),
                        "success",
                    )

        connection.commit()

    users = connection.execute(
        """
        SELECT
            id,
            username,
            display_name,
            is_admin,
            is_active,
            created_at
        FROM users
        ORDER BY
            is_admin DESC,
            id
        """
    ).fetchall()

    connection.close()

    return render_template(
        "admin_users.html",
        users=users,
        current_user=user,
        max_active_users=MAX_ACTIVE_USERS,
    )


# ============================================================
# GENERIC HELPERS
# ============================================================

def get_active_certification():
    certification = request.args.get(
        "cert",
        "CISSP",
    ).upper()

    if certification not in VALID_CERTIFICATIONS:
        return "CISSP"

    return certification


def parse_date(value):
    if not value:
        return None

    try:
        return datetime.strptime(
            value,
            "%Y-%m-%d",
        ).date()

    except ValueError:
        return None


def days_until(value):
    target = parse_date(value)

    if not target:
        return None

    return (
        target - date.today()
    ).days


def format_date(value):
    if not value:
        return "Not set"

    if isinstance(
        value,
        str,
    ):
        value = parse_date(
            value
        )

    if not value:
        return "Not set"

    return value.strftime(
        "%b %d, %Y"
    )


def get_settings(
    connection,
    user_id,
):
    rows = connection.execute(
        """
        SELECT
            key,
            value
        FROM user_settings
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchall()

    settings = {
        row["key"]: row["value"]
        for row in rows
    }

    defaults = {
        "cism_exam_date": "",
        "cissp_exam_date": "",
        "weekly_hour_target": "10",
    }

    for key, value in defaults.items():
        settings.setdefault(
            key,
            value,
        )

    return settings


# ============================================================
# HISTORICAL ATTEMPT
# ============================================================

def get_historical_attempt(
    connection,
    user_id,
    certification,
):
    attempt = connection.execute(
        """
        SELECT
            id,
            certification,
            attempt_period,
            overall_score,
            result
        FROM certification_attempts
        WHERE user_id = ?
          AND certification = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            user_id,
            certification,
        ),
    ).fetchone()

    if not attempt:
        return None

    domain_rows = connection.execute(
        """
        SELECT
            d.id,
            d.domain_number,
            d.name,
            d.weight,
            r.scaled_score
        FROM attempt_domain_results r
        JOIN domains d
            ON d.id = r.domain_id
        WHERE r.attempt_id = ?
        ORDER BY d.domain_number
        """,
        (attempt["id"],),
    ).fetchall()

    domains = []

    for row in domain_rows:
        score = row[
            "scaled_score"
        ]

        gap_to_reference = max(
            450 - score,
            0,
        )

        weighted_gap = round(
            gap_to_reference
            * (
                row["weight"]
                / 100
            ),
            2,
        )

        if score >= 450:
            historical_status = (
                "ABOVE REFERENCE"
            )

        elif score >= 425:
            historical_status = "CLOSE"

        elif score >= 400:
            historical_status = "BELOW"

        else:
            historical_status = "WEAK"

        visual_percent = round(
            max(
                min(
                    (
                        score - 200
                    )
                    / 600
                    * 100,
                    100,
                ),
                0,
            ),
            1,
        )

        pass_marker_percent = round(
            (
                450 - 200
            )
            / 600
            * 100,
            1,
        )

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
        key=lambda item:
            item["weighted_gap"],
        reverse=True,
    )

    return {
        "period":
            attempt[
                "attempt_period"
            ],

        "overall_score":
            attempt[
                "overall_score"
            ],

        "result":
            attempt["result"],

        "reference_score":
            450,

        "domains":
            domains,

        "priority":
            ranked[0]
            if ranked
            else None,

        "ranked":
            ranked,
    }


# ============================================================
# DOMAIN READINESS
# ============================================================

def calculate_color_status(
    accuracy,
    questions,
):
    if questions == 0:
        return "UNTESTED"

    if accuracy < 70:
        return "RED"

    if accuracy < 80:
        return "YELLOW"

    return "GREEN"


def calculate_readiness_status(
    certification,
    accuracy,
    questions,
):
    target = CERTIFICATION_CONFIG[
        certification
    ]["sample_target"]

    if questions == 0:
        return "UNTESTED"

    if questions < 50:
        return "LOW SAMPLE"

    if questions < target:
        return "BUILDING"

    if accuracy < 80:
        return "REMEDIATE"

    return "READY"


def build_domains(
    connection,
    user_id,
    certification,
):
    rows = connection.execute(
        """
        SELECT
            d.id,
            d.domain_number,
            d.certification,
            d.name,
            d.weight,
            COALESCE(
                uds.questions_answered,
                0
            ) AS questions_answered,
            COALESCE(
                uds.questions_correct,
                0
            ) AS questions_correct
        FROM domains d
        LEFT JOIN user_domain_stats uds
            ON uds.domain_id = d.id
           AND uds.user_id = ?
        WHERE d.certification = ?
        ORDER BY d.domain_number
        """,
        (
            user_id,
            certification,
        ),
    ).fetchall()

    target = CERTIFICATION_CONFIG[
        certification
    ]["sample_target"]

    domains = []

    for row in rows:
        questions = row[
            "questions_answered"
        ]

        correct = row[
            "questions_correct"
        ]

        accuracy = (
            round(
                correct
                / questions
                * 100,
                1,
            )
            if questions
            else 0
        )

        domains.append(
            {
                "id":
                    row["id"],

                "number":
                    row[
                        "domain_number"
                    ],

                "name":
                    row["name"],

                "weight":
                    row["weight"],

                "questions_answered":
                    questions,

                "questions_correct":
                    correct,

                "accuracy":
                    accuracy,

                "color_status":
                    calculate_color_status(
                        accuracy,
                        questions,
                    ),

                "readiness_status":
                    calculate_readiness_status(
                        certification,
                        accuracy,
                        questions,
                    ),

                "sample_target":
                    target,

                "evidence_percent":
                    min(
                        round(
                            questions
                            / target
                            * 100,
                            1,
                        ),
                        100,
                    ),

                "weakness_score":
                    (
                        round(
                            (
                                100
                                - accuracy
                            )
                            * (
                                row[
                                    "weight"
                                ]
                                / 100
                            ),
                            2,
                        )
                        if questions
                        else 999
                    ),
            }
        )

    return domains


# ============================================================
# MOCK STATS
# ============================================================

def get_mock_stats(
    connection,
    user_id,
    certification,
):
    rows = connection.execute(
        """
        SELECT
            id,
            questions_answered,
            questions_correct,
            minutes_spent,
            assessment_date
        FROM assessments
        WHERE user_id = ?
          AND certification = ?
          AND assessment_type = 'mock'
        ORDER BY
            assessment_date DESC,
            id DESC
        LIMIT 3
        """,
        (
            user_id,
            certification,
        ),
    ).fetchall()

    results = []

    for row in rows:
        questions = row[
            "questions_answered"
        ]

        correct = row[
            "questions_correct"
        ]

        accuracy = (
            round(
                correct
                / questions
                * 100,
                1,
            )
            if questions
            else 0
        )

        results.append(
            {
                "id":
                    row["id"],

                "accuracy":
                    accuracy,

                "questions":
                    questions,

                "correct":
                    correct,

                "minutes":
                    row[
                        "minutes_spent"
                    ],

                "date":
                    row[
                        "assessment_date"
                    ],
            }
        )

    average = (
        round(
            sum(
                result["accuracy"]
                for result
                in results
            )
            / len(results),
            1,
        )
        if results
        else None
    )

    return {
        "count":
            len(results),

        "average":
            average,

        "results":
            results,
    }


# ============================================================
# OVERALL READINESS
# ============================================================

def calculate_overall_readiness(
    certification,
    domains,
    mock_stats,
    open_topic_count,
):
    tested = [
        domain
        for domain in domains
        if domain[
            "questions_answered"
        ] > 0
    ]

    if not tested:
        return {
            "score": 0,
            "decision": "NO-GO",
            "reason":
                "No current domain baseline data yet.",
            "green_count": 0,
            "ready_count": 0,
            "red_count": 0,
            "total_questions": 0,
            "mock_average":
                mock_stats[
                    "average"
                ],
        }

    weighted_domain_score = round(
        sum(
            domain["accuracy"]
            * (
                domain["weight"]
                / 100
            )
            for domain
            in domains
        ),
        1,
    )

    green_count = sum(
        1
        for domain in domains
        if domain[
            "color_status"
        ] == "GREEN"
    )

    ready_count = sum(
        1
        for domain in domains
        if domain[
            "readiness_status"
        ] == "READY"
    )

    red_count = sum(
        1
        for domain in domains
        if domain[
            "color_status"
        ] == "RED"
    )

    total_questions = sum(
        domain[
            "questions_answered"
        ]
        for domain
        in domains
    )

    if (
        mock_stats["average"]
        is not None
    ):
        score = round(
            weighted_domain_score
            * 0.70
            + mock_stats[
                "average"
            ]
            * 0.30,
            1,
        )

    else:
        score = (
            weighted_domain_score
        )

    config = CERTIFICATION_CONFIG[
        certification
    ]

    all_tested = (
        len(tested)
        == config[
            "domain_count"
        ]
    )

    required_total = (
        config[
            "sample_target"
        ]
        * config[
            "domain_count"
        ]
    )

    if (
        all_tested
        and ready_count
        == config[
            "domain_count"
        ]
        and total_questions
        >= required_total
        and mock_stats[
            "count"
        ] >= 2
        and mock_stats[
            "average"
        ] is not None
        and mock_stats[
            "average"
        ] >= config[
            "mock_target"
        ]
        and open_topic_count
        <= 3
    ):
        decision = "GO"

        reason = (
            "Domain evidence, mock performance, "
            "and readiness gates are satisfied."
        )

    elif (
        all_tested
        and red_count == 0
        and ready_count
        >= ceil(
            config[
                "domain_count"
            ]
            * 0.75
        )
        and mock_stats[
            "count"
        ] >= 1
        and mock_stats[
            "average"
        ] is not None
        and mock_stats[
            "average"
        ] >= 75
    ):
        decision = "HOLD"

        reason = (
            "Performance is close. "
            "Close remaining readiness gaps "
            "before exam day."
        )

    else:
        decision = "NO-GO"

        reason = (
            "Current evidence does not yet "
            "support an exam-ready decision."
        )

    return {
        "score":
            score,

        "decision":
            decision,

        "reason":
            reason,

        "green_count":
            green_count,

        "ready_count":
            ready_count,

        "red_count":
            red_count,

        "total_questions":
            total_questions,

        "mock_average":
            mock_stats[
                "average"
            ],
    }


# ============================================================
# ADAPTIVE PRESCRIPTION
# ============================================================

def choose_priority_domain(
    certification,
    domains,
    historical_attempt=None,
):
    if not domains:
        return None

    red = [
        domain
        for domain in domains
        if (
            domain[
                "questions_answered"
            ] >= 20
            and domain[
                "color_status"
            ] == "RED"
        )
    ]

    if red:
        return max(
            red,
            key=lambda domain:
                domain[
                    "weakness_score"
                ],
        )

    yellow = [
        domain
        for domain in domains
        if (
            domain[
                "questions_answered"
            ] >= 20
            and domain[
                "color_status"
            ] == "YELLOW"
        )
    ]

    if yellow:
        return max(
            yellow,
            key=lambda domain:
                domain[
                    "weakness_score"
                ],
        )

    if (
        certification == "CISM"
        and historical_attempt
    ):
        thin_ids = {
            domain["id"]
            for domain in domains
            if domain[
                "questions_answered"
            ] < 50
        }

        historical_candidates = [
            historical
            for historical
            in historical_attempt[
                "ranked"
            ]
            if historical["id"]
            in thin_ids
        ]

        if historical_candidates:
            chosen_id = (
                historical_candidates[
                    0
                ]["id"]
            )

            return next(
                (
                    domain
                    for domain
                    in domains
                    if domain[
                        "id"
                    ] == chosen_id
                ),
                None,
            )

    thin = [
        domain
        for domain in domains
        if (
            domain[
                "questions_answered"
            ]
            < domain[
                "sample_target"
            ]
        )
    ]

    if thin:
        return max(
            thin,
            key=lambda domain:
                (
                    domain[
                        "weight"
                    ],
                    -domain[
                        "questions_answered"
                    ],
                ),
        )

    return min(
        domains,
        key=lambda domain:
            domain[
                "accuracy"
            ],
    )


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
            "headline":
                "No domain data yet",
            "summary":
                "Log an assessment to generate a data-driven prescription.",
            "actions": [],
        }

    questions = target[
        "questions_answered"
    ]

    accuracy = target[
        "accuracy"
    ]

    remaining = max(
        target[
            "sample_target"
        ]
        - questions,
        0,
    )

    if questions == 0:
        summary = (
            f"Start with {target['name']}. "
            f"It has no current baseline yet."
        )

        actions = [
            (
                f"Run a fresh {certification} "
                f"question set for "
                f"{target['name']}."
            ),
            (
                "Do not study the domain first; "
                "measure it first."
            ),
            (
                "Review every miss "
                "before remediation."
            ),
        ]

    elif (
        target[
            "color_status"
        ] == "RED"
    ):
        summary = (
            f"{target['name']} is the primary "
            f"current weakness at {accuracy}% "
            f"across {questions} questions."
        )

        actions = [
            (
                "Review every miss from "
                "the most recent set."
            ),
            (
                "Remediate only the concepts "
                "that actually failed."
            ),
            (
                "Retest with unseen questions."
            ),
        ]

    elif (
        target[
            "color_status"
        ] == "YELLOW"
    ):
        summary = (
            f"{target['name']} is close but still "
            f"below the 80% target: {accuracy}% "
            f"across {questions} questions."
        )

        actions = [
            (
                "Run another unseen question set."
            ),
            (
                "Review all misses and "
                "interpretation errors."
            ),
            (
                "Use targeted remediation only "
                "if the same concepts repeat."
            ),
        ]

    elif remaining > 0:
        summary = (
            f"{target['name']} is currently green "
            f"at {accuracy}%, but the sample is "
            f"still thin: {questions}/"
            f"{target['sample_target']}."
        )

        actions = [
            (
                f"Build another {remaining} "
                f"questions of evidence "
                f"over multiple sessions."
            ),
            (
                "Keep using unseen questions."
            ),
            (
                "Do not over-study a green domain "
                "just to chase a perfect score."
            ),
        ]

    else:
        summary = (
            f"{target['name']} is ready. "
            f"The priority shifts to mixed "
            f"validation and mock performance."
        )

        actions = [
            (
                "Run mixed-domain assessments."
            ),
            (
                "Use domain-only work only "
                "when a new weakness appears."
            ),
            (
                "Protect recent mock performance "
                "at or above 80%."
            ),
        ]

    if (
        certification == "CISM"
        and historical_attempt
        and questions < 50
    ):
        historical = next(
            (
                item
                for item
                in historical_attempt[
                    "domains"
                ]
                if item["id"]
                == target["id"]
            ),
            None,
        )

        if historical:
            summary += (
                " Historical exam baseline "
                f"for this domain was "
                f"{historical['score']} scaled."
            )

    if phase_code in {
        "CISM_FINAL",
        "CISSP_MOCK",
    }:
        actions = [
            (
                "Use mixed sets / mocks as "
                "the primary evidence source."
            ),
            (
                "Remediate only recurring misses."
            ),
            (
                "Do not reopen full books "
                "or courses."
            ),
        ]

    return {
        "adaptive": True,
        "badge": "DATA DRIVEN",
        "headline":
            target["name"],
        "summary":
            summary,
        "actions":
            actions,
        "domain_id":
            target["id"],
        "accuracy":
            accuracy,
        "questions":
            questions,
        "sample_target":
            target[
                "sample_target"
            ],
        "remaining":
            remaining,
        "readiness_status":
            target[
                "readiness_status"
            ],
        "color_status":
            target[
                "color_status"
            ],
    }


def determine_next_action(
    certification,
    domains,
    historical_attempt=None,
):
    prescription = (
        build_adaptive_prescription(
            certification,
            "GENERIC",
            domains,
            {
                "score": 0,
                "decision":
                    "NO-GO",
            },
            {
                "average": None,
                "count": 0,
            },
            historical_attempt,
        )
    )

    return {
        "priority":
            (
                "VALIDATE / REMEDIATE"
                if prescription[
                    "adaptive"
                ]
                else
                "ESTABLISH BASELINE"
            ),

        "title":
            prescription[
                "headline"
            ],

        "instruction":
            prescription[
                "summary"
            ],
    }


# ============================================================
# CAMPAIGN
# ============================================================

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

    cism_date = parse_date(
        settings.get(
            "cism_exam_date",
            "",
        )
    )

    cissp_date = parse_date(
        settings.get(
            "cissp_exam_date",
            "",
        )
    )

    if not cism_date:
        cism_date = (
            today
            + timedelta(
                days=40
            )
        )

    cism_days = (
        cism_date
        - today
    ).days

    intensive_start = (
        cism_date
        - timedelta(
            days=21
        )
    )

    final_start = (
        cism_date
        - timedelta(
            days=6
        )
    )

    transition_end = (
        cism_date
        + timedelta(
            days=7
        )
    )

    domain_build_end = (
        cism_date
        + timedelta(
            days=49
        )
    )

    validation_end = (
        cism_date
        + timedelta(
            days=84
        )
    )

    if cism_days > 21:
        phase_code = (
            "CISM_PRIMARY"
        )

        priority_cert = "CISM"

    elif cism_days >= 7:
        phase_code = (
            "CISM_INTENSIVE"
        )

        priority_cert = "CISM"

    elif cism_days >= 0:
        phase_code = (
            "CISM_FINAL"
        )

        priority_cert = "CISM"

    else:
        days_after_cism = abs(
            cism_days
        )

        priority_cert = "CISSP"

        if days_after_cism <= 7:
            phase_code = (
                "CISSP_TRANSITION"
            )

        elif days_after_cism <= 49:
            phase_code = (
                "CISSP_BUILD"
            )

        elif days_after_cism <= 84:
            phase_code = (
                "CISSP_VALIDATION"
            )

        else:
            phase_code = (
                "CISSP_MOCK"
            )

    if (
        cissp_date
        and today > cism_date
        and 0
        <= (
            cissp_date
            - today
        ).days
        <= 21
    ):
        phase_code = (
            "CISSP_MOCK"
        )

        priority_cert = "CISSP"

    phase_data = {
        "CISM_PRIMARY": {
            "title":
                "CISM Primary",

            "dates":
                (
                    f"Now → "
                    f"{format_date(intensive_start - timedelta(days=1))}"
                ),

            "work":
                "Validate weaknesses and build current evidence.",

            "objective":
                (
                    "Build current CISM evidence without wasting time "
                    "rereading material you already know."
                ),

            "study_items": [
                (
                    "Pocket Prep is the primary engine."
                ),
                (
                    "Review every miss."
                ),
                (
                    "Use Chapple only for demonstrated gaps."
                ),
                (
                    "Use YouTube only if the concept still does not click."
                ),
                (
                    "Keep CISSP in maintenance mode."
                ),
            ],

            "targets": [
                (
                    "At least 50 current questions per CISM domain."
                ),
                (
                    "Move every domain toward 80%+."
                ),
                (
                    "Use current evidence to confirm actual weaknesses."
                ),
            ],

            "resources":
                (
                    "Pocket Prep → Chapple CISM Study Guide → YouTube."
                ),

            "exit":
                (
                    "All four CISM domains have meaningful current evidence."
                ),
        },

        "CISM_INTENSIVE": {
            "title":
                "CISM Intensive",

            "dates":
                (
                    f"{format_date(intensive_start)} → "
                    f"{format_date(final_start - timedelta(days=1))}"
                ),

            "work":
                "Question-driven CISM remediation.",

            "objective":
                (
                    "Turn known weaknesses into stable mixed-question performance."
                ),

            "study_items": [
                (
                    "Run 30–50 question mixed sets."
                ),
                (
                    "Attack the lowest-performing weighted domain first."
                ),
                (
                    "Review every miss before adding more questions."
                ),
                (
                    "Use Chapple and YouTube only for targeted remediation."
                ),
            ],

            "targets": [
                (
                    "80%+ on fresh mixed sets."
                ),
                (
                    "Build toward 100 questions per CISM domain."
                ),
                (
                    "No domain consistently below 70%."
                ),
            ],

            "resources":
                (
                    "Pocket Prep → Chapple CISM Study Guide → YouTube."
                ),

            "exit":
                (
                    "No major red domain and mixed scores are stable."
                ),
        },

        "CISM_FINAL": {
            "title":
                "CISM Final",

            "dates":
                (
                    f"{format_date(final_start)} → "
                    f"{format_date(cism_date)}"
                ),

            "work":
                "Final review and exam execution.",

            "objective":
                (
                    "Protect decision quality and avoid destabilizing preparation."
                ),

            "study_items": [
                (
                    "Mixed Pocket Prep only."
                ),
                (
                    "Review recurring misses and weak topics."
                ),
                (
                    "No broad rereading."
                ),
                (
                    "No new resources."
                ),
            ],

            "targets": [
                (
                    "Recent mixed performance around or above 80%."
                ),
                (
                    "No unresolved major weakness."
                ),
                (
                    "Protect sleep and exam execution."
                ),
            ],

            "resources":
                (
                    "Pocket Prep + targeted Chapple review."
                ),

            "exit":
                "Sit the CISM exam.",
        },

        "CISSP_TRANSITION": {
            "title":
                "CISSP Transition",

            "dates":
                (
                    f"{format_date(cism_date + timedelta(days=1))} → "
                    f"{format_date(transition_end)}"
                ),

            "work":
                "Baseline and restart CISSP curriculum.",

            "objective":
                (
                    "Switch mental models from CISM to CISSP and identify the real gaps."
                ),

            "study_items": [
                (
                    "Resume ISC2 self-paced."
                ),
                (
                    "Run baseline Pocket Prep across all eight domains."
                ),
                (
                    "Use Chapple only when the baseline exposes a specific weakness."
                ),
            ],

            "targets": [
                (
                    "Every CISSP domain has baseline data."
                ),
                (
                    "Identify red, yellow, and green domains."
                ),
            ],

            "resources":
                (
                    "ISC2 Self-Paced → Pocket Prep → Chapple → "
                    "7th Edition / targeted video."
                ),

            "exit":
                (
                    "All 8 domains have baseline data."
                ),
        },

        "CISSP_BUILD": {
            "title":
                "CISSP Domain Build",

            "dates":
                (
                    f"{format_date(transition_end + timedelta(days=1))} → "
                    f"{format_date(domain_build_end)}"
                ),

            "work":
                "ISC2 → Pocket Prep → Chapple → retest.",

            "objective":
                (
                    "Build competence and enough evidence to trust the percentages."
                ),

            "study_items": [
                (
                    "Use Next Action to choose the priority domain."
                ),
                (
                    "Complete relevant ISC2 material."
                ),
                (
                    "Run 25–40 Pocket Prep questions."
                ),
                (
                    "Review every miss."
                ),
                (
                    "Retest with unseen questions."
                ),
            ],

            "targets": [
                (
                    "80%+ accuracy target."
                ),
                (
                    "Build toward 150 questions per domain."
                ),
                (
                    "No red domain without active remediation."
                ),
            ],

            "resources":
                (
                    "ISC2 Self-Paced → Pocket Prep → Chapple → "
                    "7th Edition / targeted video."
                ),

            "exit":
                (
                    "Most domains are green or approaching green."
                ),
        },

        "CISSP_VALIDATION": {
            "title":
                "CISSP Validation",

            "dates":
                (
                    f"{format_date(domain_build_end + timedelta(days=1))} → "
                    f"{format_date(validation_end)}"
                ),

            "work":
                "150/domain target and mixed testing.",

            "objective":
                (
                    "Prove that domain knowledge survives mixed testing."
                ),

            "study_items": [
                (
                    "Shift most question work to mixed sets."
                ),
                (
                    "Use domain-only sets for yellow/red areas."
                ),
                (
                    "Begin Mock Readiness Exams."
                ),
                (
                    "Do not restart entire courses or books."
                ),
            ],

            "targets": [
                (
                    "150 questions per domain."
                ),
                (
                    "80%+ cumulative accuracy in each domain."
                ),
                (
                    "At least one serious mock readiness exam."
                ),
                (
                    "No red domains."
                ),
            ],

            "resources":
                (
                    "Pocket Prep dominant; ISC2/Chapple become remediation references."
                ),

            "exit":
                (
                    "Mock performance becomes the main readiness signal."
                ),
        },

        "CISSP_MOCK": {
            "title":
                "CISSP Mock Readiness",

            "dates":
                (
                    f"{format_date(validation_end + timedelta(days=1))} → Exam"
                ),

            "work":
                "Mock exams and targeted cleanup.",

            "objective":
                (
                    "Validate exam-level performance without relearning "
                    "material you already know."
                ),

            "study_items": [
                (
                    "Run full mixed mock exams."
                ),
                (
                    "Analyze miss patterns after every mock."
                ),
                (
                    "Remediate recurring topics only."
                ),
                (
                    "Do not add new resources."
                ),
            ],

            "targets": [
                (
                    "At least two serious mock exams."
                ),
                (
                    "Recent mock average at or above 80%."
                ),
                (
                    "All 8 domains at or above 80% with strong evidence."
                ),
            ],

            "resources":
                (
                    "Pocket Prep / mock source → targeted Chapple or ISC2 remediation."
                ),

            "exit":
                (
                    "Dashboard reaches GO and recent performance supports sitting the CISSP."
                ),
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

    current_index = (
        ordered_codes.index(
            phase_code
        )
    )

    phases = []

    for index, code in enumerate(
        ordered_codes
    ):
        item = dict(
            phase_data[code]
        )

        item["code"] = code

        item["status"] = (
            "COMPLETE"
            if index
            < current_index

            else
            "CURRENT"
            if index
            == current_index

            else
            "UPCOMING"
        )

        if code.startswith(
            "CISM"
        ):
            item[
                "adaptive_prescription"
            ] = (
                build_adaptive_prescription(
                    "CISM",
                    code,
                    cism_domains,
                    cism_readiness,
                    cism_mock_stats,
                    cism_historical_attempt,
                )
            )

        else:
            item[
                "adaptive_prescription"
            ] = (
                build_adaptive_prescription(
                    "CISSP",
                    code,
                    cissp_domains,
                    cissp_readiness,
                    cissp_mock_stats,
                    None,
                )
            )

        phases.append(
            item
        )

    active_phase = next(
        phase
        for phase
        in phases
        if phase[
            "code"
        ] == phase_code
    )

    adaptive = active_phase[
        "adaptive_prescription"
    ]

    banner = {
        "certification":
            priority_cert,

        "phase":
            active_phase[
                "title"
            ].upper(),

        "headline":
            (
                f"YOU SHOULD BE STUDYING "
                f"{priority_cert}"
            ),

        "prescription":
            (
                f"{adaptive['headline']}: "
                f"{adaptive['summary']}"
                if adaptive[
                    "adaptive"
                ]
                else active_phase[
                    "work"
                ]
            ),

        "data_driven":
            adaptive[
                "adaptive"
            ],
    }

    return {
        "banner":
            banner,

        "phases":
            phases,

        "phase_code":
            phase_code,
    }


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
@login_required
def dashboard():
    user = current_user()

    active_cert = (
        get_active_certification()
    )

    connection = (
        get_db_connection()
    )

    settings = get_settings(
        connection,
        user["id"],
    )

    cism_domains = build_domains(
        connection,
        user["id"],
        "CISM",
    )

    cissp_domains = build_domains(
        connection,
        user["id"],
        "CISSP",
    )

    cism_historical_attempt = (
        get_historical_attempt(
            connection,
            user["id"],
            "CISM",
        )
    )

    active_historical_attempt = (
        cism_historical_attempt
        if active_cert
        == "CISM"
        else None
    )

    active_domains = (
        cism_domains
        if active_cert
        == "CISM"
        else cissp_domains
    )

    open_topics = connection.execute(
        """
        SELECT
            w.id,
            w.domain_id,
            w.topic,
            d.domain_number,
            d.name AS domain_name
        FROM weak_topics w
        JOIN domains d
            ON d.id = w.domain_id
        WHERE w.user_id = ?
          AND w.status = 'OPEN'
          AND w.certification = ?
        ORDER BY w.created_at DESC
        """,
        (
            user["id"],
            active_cert,
        ),
    ).fetchall()

    recent_assessments = (
        connection.execute(
            """
            SELECT
                a.id,
                a.assessment_type,
                a.source,
                a.questions_answered,
                a.questions_correct,
                a.minutes_spent,
                a.assessment_date,
                d.name AS domain_name
            FROM assessments a
            LEFT JOIN domains d
                ON d.id = a.domain_id
            WHERE a.user_id = ?
              AND a.certification = ?
            ORDER BY
                a.assessment_date DESC,
                a.id DESC
            LIMIT 8
            """,
            (
                user["id"],
                active_cert,
            ),
        ).fetchall()
    )

    recent_study = (
        connection.execute(
            """
            SELECT
                s.id,
                s.resource,
                s.minutes_studied,
                s.session_date,
                d.name AS domain_name
            FROM study_sessions s
            LEFT JOIN domains d
                ON d.id = s.domain_id
            WHERE s.user_id = ?
              AND s.certification = ?
            ORDER BY
                s.session_date DESC,
                s.id DESC
            LIMIT 8
            """,
            (
                user["id"],
                active_cert,
            ),
        ).fetchall()
    )

    total_study_row = (
        connection.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        minutes_studied
                    ),
                    0
                ) AS minutes
            FROM study_sessions
            WHERE user_id = ?
              AND certification = ?
            """,
            (
                user["id"],
                active_cert,
            ),
        ).fetchone()
    )

    total_assessment_row = (
        connection.execute(
            """
            SELECT
                COALESCE(
                    SUM(
                        minutes_spent
                    ),
                    0
                ) AS minutes
            FROM assessments
            WHERE user_id = ?
              AND certification = ?
            """,
            (
                user["id"],
                active_cert,
            ),
        ).fetchone()
    )

    cism_open_count = (
        connection.execute(
            """
            SELECT
                COUNT(*) AS count
            FROM weak_topics
            WHERE user_id = ?
              AND status = 'OPEN'
              AND certification = 'CISM'
            """,
            (user["id"],),
        ).fetchone()[
            "count"
        ]
    )

    cissp_open_count = (
        connection.execute(
            """
            SELECT
                COUNT(*) AS count
            FROM weak_topics
            WHERE user_id = ?
              AND status = 'OPEN'
              AND certification = 'CISSP'
            """,
            (user["id"],),
        ).fetchone()[
            "count"
        ]
    )

    cism_mock_stats = (
        get_mock_stats(
            connection,
            user["id"],
            "CISM",
        )
    )

    cissp_mock_stats = (
        get_mock_stats(
            connection,
            user["id"],
            "CISSP",
        )
    )

    connection.close()

    cism_readiness = (
        calculate_overall_readiness(
            "CISM",
            cism_domains,
            cism_mock_stats,
            cism_open_count,
        )
    )

    cissp_readiness = (
        calculate_overall_readiness(
            "CISSP",
            cissp_domains,
            cissp_mock_stats,
            cissp_open_count,
        )
    )

    active_readiness = (
        cism_readiness
        if active_cert
        == "CISM"
        else cissp_readiness
    )

    active_mock_stats = (
        cism_mock_stats
        if active_cert
        == "CISM"
        else cissp_mock_stats
    )

    total_questions = sum(
        domain[
            "questions_answered"
        ]
        for domain
        in active_domains
    )

    total_correct = sum(
        domain[
            "questions_correct"
        ]
        for domain
        in active_domains
    )

    overall_accuracy = (
        round(
            total_correct
            / total_questions
            * 100,
            1,
        )
        if total_questions
        else 0
    )

    total_minutes = (
        total_study_row[
            "minutes"
        ]
        + total_assessment_row[
            "minutes"
        ]
    )

    next_action = (
        determine_next_action(
            active_cert,
            active_domains,
            active_historical_attempt,
        )
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

        current_user=user,

        active_cert=
            active_cert,

        config=
            CERTIFICATION_CONFIG[
                active_cert
            ],

        domains=
            active_domains,

        settings=
            settings,

        open_topics=
            open_topics,

        recent_assessments=
            recent_assessments,

        recent_study=
            recent_study,

        mock_stats=
            active_mock_stats,

        historical_attempt=
            active_historical_attempt,

        total_questions=
            total_questions,

        overall_accuracy=
            overall_accuracy,

        total_hours=
            round(
                total_minutes
                / 60,
                1,
            ),

        readiness=
            active_readiness,

        next_action=
            next_action,

        campaign=
            campaign,

        cism_days=
            days_until(
                settings.get(
                    "cism_exam_date",
                    "",
                )
            ),

        cissp_days=
            days_until(
                settings.get(
                    "cissp_exam_date",
                    "",
                )
            ),
    )


# ============================================================
# LOG ASSESSMENT
# ============================================================

@app.route(
    "/log-assessment",
    methods=["POST"],
)
@login_required
def log_assessment():
    user = current_user()

    certification = request.form[
        "certification"
    ].upper()

    if certification not in VALID_CERTIFICATIONS:
        certification = "CISSP"

    assessment_type = request.form[
        "assessment_type"
    ]

    source = request.form[
        "source"
    ].strip()

    try:
        questions = int(
            request.form[
                "questions"
            ]
        )

        correct = int(
            request.form[
                "correct"
            ]
        )

        minutes = int(
            request.form.get(
                "minutes",
                0,
            )
            or 0
        )

        knowledge = int(
            request.form.get(
                "knowledge_misses",
                0,
            )
            or 0
        )

        interpretation = int(
            request.form.get(
                "interpretation_misses",
                0,
            )
            or 0
        )

        mindset = int(
            request.form.get(
                "mindset_misses",
                0,
            )
            or 0
        )

    except ValueError:
        flash(
            "Assessment contains invalid numbers.",
            "error",
        )

        return redirect(
            url_for(
                "dashboard",
                cert=certification,
            )
        )

    if (
        questions <= 0
        or correct < 0
        or correct > questions
        or minutes < 0
    ):
        flash(
            "Assessment totals are invalid.",
            "error",
        )

        return redirect(
            url_for(
                "dashboard",
                cert=certification,
            )
        )

    misses = (
        questions
        - correct
    )

    if (
        knowledge < 0
        or interpretation < 0
        or mindset < 0
        or (
            knowledge
            + interpretation
            + mindset
        ) > misses
    ):
        flash(
            "Miss classifications cannot exceed total missed questions.",
            "error",
        )

        return redirect(
            url_for(
                "dashboard",
                cert=certification,
            )
        )

    notes = request.form.get(
        "notes",
        "",
    ).strip()

    domain_id = request.form.get(
        "domain_id"
    )

    if assessment_type != "single":
        domain_id = None

    elif domain_id:
        domain_id = int(
            domain_id
        )

    connection = get_db_connection()

    cursor = connection.execute(
        """
        INSERT INTO assessments (
            user_id,
            certification,
            assessment_type,
            source,
            domain_id,
            questions_answered,
            questions_correct,
            knowledge_misses,
            interpretation_misses,
            mindset_misses,
            minutes_spent,
            notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
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

    assessment_id = (
        cursor.lastrowid
    )

    if (
        assessment_type
        == "single"
        and domain_id
    ):
        connection.execute(
            """
            INSERT INTO user_domain_stats (
                user_id,
                domain_id,
                questions_answered,
                questions_correct
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(
                user_id,
                domain_id
            )
            DO UPDATE SET
                questions_answered =
                    questions_answered
                    + excluded.questions_answered,
                questions_correct =
                    questions_correct
                    + excluded.questions_correct
            """,
            (
                user["id"],
                domain_id,
                questions,
                correct,
            ),
        )

    if assessment_type == "mixed":
        domain_rows = (
            connection.execute(
                """
                SELECT
                    id,
                    domain_number
                FROM domains
                WHERE certification = ?
                ORDER BY domain_number
                """,
                (certification,),
            ).fetchall()
        )

        breakdown = []

        for domain in domain_rows:
            number = domain[
                "domain_number"
            ]

            q_value = request.form.get(
                f"domain_{number}_questions",
                "",
            )

            c_value = request.form.get(
                f"domain_{number}_correct",
                "",
            )

            if not q_value:
                continue

            try:
                domain_questions = int(
                    q_value
                )

                domain_correct = int(
                    c_value
                    or 0
                )

            except ValueError:
                continue

            if domain_questions <= 0:
                continue

            if (
                domain_correct < 0
                or domain_correct
                > domain_questions
            ):
                continue

            breakdown.append(
                (
                    domain["id"],
                    domain_questions,
                    domain_correct,
                )
            )

        if breakdown:
            breakdown_questions = sum(
                item[1]
                for item
                in breakdown
            )

            breakdown_correct = sum(
                item[2]
                for item
                in breakdown
            )

            if (
                breakdown_questions
                != questions
                or breakdown_correct
                != correct
            ):
                connection.rollback()
                connection.close()

                flash(
                    (
                        "Mixed-domain breakdown does not match "
                        "the overall Correct / Answered totals."
                    ),
                    "error",
                )

                return redirect(
                    url_for(
                        "dashboard",
                        cert=certification,
                    )
                )

            for (
                breakdown_domain_id,
                domain_questions,
                domain_correct,
            ) in breakdown:

                connection.execute(
                    """
                    INSERT INTO assessment_domain_results (
                        assessment_id,
                        domain_id,
                        questions_answered,
                        questions_correct
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
                    INSERT INTO user_domain_stats (
                        user_id,
                        domain_id,
                        questions_answered,
                        questions_correct
                    )
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(
                        user_id,
                        domain_id
                    )
                    DO UPDATE SET
                        questions_answered =
                            questions_answered
                            + excluded.questions_answered,
                        questions_correct =
                            questions_correct
                            + excluded.questions_correct
                    """,
                    (
                        user["id"],
                        breakdown_domain_id,
                        domain_questions,
                        domain_correct,
                    ),
                )

    connection.commit()
    connection.close()

    flash(
        "Assessment logged.",
        "success",
    )

    return redirect(
        url_for(
            "dashboard",
            cert=certification,
        )
    )


# ============================================================
# LOG STUDY
# ============================================================

@app.route(
    "/log-study",
    methods=["POST"],
)
@login_required
def log_study():
    user = current_user()

    certification = request.form[
        "certification"
    ].upper()

    domain_id = request.form.get(
        "study_domain_id"
    )

    domain_id = (
        int(domain_id)
        if domain_id
        else None
    )

    resource = request.form[
        "study_resource"
    ].strip()

    try:
        minutes = int(
            request.form[
                "study_minutes"
            ]
        )

    except ValueError:
        minutes = 0

    notes = request.form.get(
        "study_notes",
        "",
    ).strip()

    if minutes <= 0:
        flash(
            "Study time must be greater than zero.",
            "error",
        )

        return redirect(
            url_for(
                "dashboard",
                cert=certification,
            )
        )

    connection = get_db_connection()

    connection.execute(
        """
        INSERT INTO study_sessions (
            user_id,
            certification,
            domain_id,
            resource,
            minutes_studied,
            notes
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            certification,
            domain_id,
            resource,
            minutes,
            notes,
        ),
    )

    connection.commit()
    connection.close()

    flash(
        "Study session logged.",
        "success",
    )

    return redirect(
        url_for(
            "dashboard",
            cert=certification,
        )
    )


# ============================================================
# WEAK TOPICS
# ============================================================

@app.route(
    "/add-topic",
    methods=["POST"],
)
@login_required
def add_topic():
    user = current_user()

    certification = request.form[
        "certification"
    ].upper()

    topic = request.form[
        "topic"
    ].strip()

    domain_id = int(
        request.form[
            "domain_id"
        ]
    )

    if not topic:
        return redirect(
            url_for(
                "dashboard",
                cert=certification,
            )
        )

    connection = get_db_connection()

    connection.execute(
        """
        INSERT INTO weak_topics (
            user_id,
            certification,
            domain_id,
            topic
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            user["id"],
            certification,
            domain_id,
            topic,
        ),
    )

    connection.commit()
    connection.close()

    return redirect(
        url_for(
            "dashboard",
            cert=certification,
        )
    )


@app.route(
    "/resolve-topic/<int:topic_id>",
    methods=["POST"],
)
@login_required
def resolve_topic(
    topic_id,
):
    user = current_user()

    certification = request.form[
        "certification"
    ].upper()

    connection = get_db_connection()

    connection.execute(
        """
        UPDATE weak_topics
        SET
            status = 'RESOLVED',
            resolved_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND user_id = ?
        """,
        (
            topic_id,
            user["id"],
        ),
    )

    connection.commit()
    connection.close()

    return redirect(
        url_for(
            "dashboard",
            cert=certification,
        )
    )


# ============================================================
# SETTINGS
# ============================================================

@app.route(
    "/settings",
    methods=["POST"],
)
@login_required
def update_settings():
    user = current_user()

    active_cert = request.form.get(
        "active_cert",
        "CISSP",
    )

    values = {
        "cism_exam_date":
            request.form.get(
                "cism_exam_date",
                "",
            ),

        "cissp_exam_date":
            request.form.get(
                "cissp_exam_date",
                "",
            ),

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
            INSERT INTO user_settings (
                user_id,
                key,
                value
            )
            VALUES (?, ?, ?)
            ON CONFLICT(
                user_id,
                key
            )
            DO UPDATE SET
                value = excluded.value
            """,
            (
                user["id"],
                key,
                value,
            ),
        )

    connection.commit()
    connection.close()

    flash(
        "Campaign settings updated.",
        "success",
    )

    return redirect(
        url_for(
            "dashboard",
            cert=active_cert,
        )
    )


if __name__ == "__main__":
    initialize_database()

    app.run(
        debug=True,
        port=5001,
    )

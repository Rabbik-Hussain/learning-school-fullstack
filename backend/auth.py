from fastapi import APIRouter
from backend.db import get_connection
from pwdlib import PasswordHash
from pydantic import BaseModel
from fastapi import HTTPException
import jwt

JWT_SECRET = "learning-school-development-secret"

router = APIRouter()
password_hash = PasswordHash.recommended()


def create_access_token(user_id: int):
    payload = {
        "user_id": user_id
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )


def decode_access_token(token: str):
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )
        return payload
    except jwt.InvalidTokenError:
        return None


def get_current_user(token: str):
    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token."
        )

    return payload["user_id"]


class RegisterRequest(BaseModel):
    teacher_id: str
    password: str
    first_name: str
    last_name: str | None = None
    profile_pic: str | None = None
    signature: str | None = None
    designation: str
    institution_name: str | None = None
    institution_id: int | None = None


class LoginRequest(BaseModel):
    teacher_id: str
    password: str


@router.post("/register")
def register_user(data: RegisterRequest):
    conn = get_connection()

    try:
        existing_users = conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        if existing_users == 0:
            if data.designation != "head_teacher":
                return {
                    "message": "First registration must be a Head Teacher."
                }

            institution = conn.execute(
                """
                INSERT INTO institutions (name)
                VALUES (%s)
                RETURNING id
                """,
                (data.institution_name,)
            ).fetchone()

            institution_id = institution[0]

            hashed_password = password_hash.hash(data.password)

            user = conn.execute(
                """
                INSERT INTO users (
                    institution_id,
                    teacher_id,
                    password_hash,
                    first_name,
                    last_name,
                    profile_pic,
                    signature,
                    designation,
                    status,
                    is_admin
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, 'active', TRUE
                )
                RETURNING id
                """,
                (
                    institution_id,
                    data.teacher_id,
                    hashed_password,
                    data.first_name,
                    data.last_name,
                    data.profile_pic,
                    data.signature,
                    data.designation
                )
            ).fetchone()

            conn.commit()

            return {
                "message": "First Head Teacher registered as Admin!",
                "institution_id": institution_id,
                "user_id": user[0],
                "status": "active",
                "is_admin": True
            }

        if data.institution_id is None:
            return {
                "message": "Institution ID is required for subsequent registration."
            }

        institution_exists = conn.execute(
            """
            SELECT id
            FROM institutions
            WHERE id = %s
            """,
            (data.institution_id,)
        ).fetchone()

        if institution_exists is None:
            return {
                "message": "Institution not found."
            }

        hashed_password = password_hash.hash(data.password)

        user = conn.execute(
            """
            INSERT INTO users (
                institution_id,
                teacher_id,
                password_hash,
                first_name,
                last_name,
                profile_pic,
                signature,
                designation,
                status,
                is_admin
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, 'pending', FALSE
            )
            RETURNING id
            """,
            (
                data.institution_id,
                data.teacher_id,
                hashed_password,
                data.first_name,
                data.last_name,
                data.profile_pic,
                data.signature,
                data.designation
            )
        ).fetchone()

        conn.execute(
            """
            INSERT INTO approval_requests (
                institution_id,
                request_type,
                user_id,
                status
            )
            VALUES (%s, 'registration', %s, 'pending')
            """,
            (
                data.institution_id,
                user[0]
            )
        )

        conn.commit()

        return {
            "message": "Registration request sent to Admin!",
            "user_id": user[0],
            "institution_id": data.institution_id,
            "status": "pending",
            "is_admin": False
        }

    finally:
        conn.close()


@router.get("/me")
def get_my_profile(token: str):
    user_id = get_current_user(token)

    conn = get_connection()

    try:
        user = conn.execute(
            """
            SELECT
                id,
                institution_id,
                teacher_id,
                first_name,
                last_name,
                designation,
                status,
                is_admin
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        ).fetchone()

        if user is None:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        return {
            "user_id": user[0],
            "institution_id": user[1],
            "teacher_id": user[2],
            "first_name": user[3],
            "last_name": user[4],
            "designation": user[5],
            "status": user[6],
            "is_admin": user[7]
        }

    finally:
        conn.close()


@router.get("/test")
def auth_test():
    return {
        "message": "Auth backend is working!"
    }


@router.post("/login")
def login_user(data: LoginRequest):
    conn = get_connection()

    try:
        user = conn.execute(
            """
            SELECT
                id,
                institution_id,
                teacher_id,
                password_hash,
                first_name,
                last_name,
                designation,
                status,
                is_admin
            FROM users
            WHERE teacher_id = %s
            """,
            (data.teacher_id,)
        ).fetchone()

        if user is None:
            return {
                "message": "Invalid Teacher ID or password."
            }

        if not password_hash.verify(
            data.password,
            user[3]
        ):
            return {
                "message": "Invalid Teacher ID or password."
            }

        if user[7] != "active":
            return {
                "message": "Your account is not active yet."
            }

        access_token = create_access_token(user[0])

        return {
            "message": "Login successful!",
            "access_token": access_token,
            "user_id": user[0],
            "institution_id": user[1],
            "teacher_id": user[2],
            "first_name": user[4],
            "last_name": user[5],
            "designation": user[6],
            "status": user[7],
            "is_admin": user[8]
        }

    finally:
        conn.close()


class ApprovalRequest(BaseModel):
    request_id: int
    action: str


class RemoveTeacherRequest(BaseModel):
    teacher_id: str
    password: str


class RemoveDirectorRequest(BaseModel):
    director_id: str
    password: str


@router.post("/remove-teacher")
def request_teacher_removal(data: RemoveTeacherRequest, token: str):
    requester_id = get_current_user(token)

    conn = get_connection()

    try:
        requester = conn.execute(
            """
            SELECT institution_id
            FROM users
            WHERE id = %s
              AND status = 'active'
            """,
            (requester_id,)
        ).fetchone()

        if requester is None:
            return {
                "message": "Active user not found."
            }

        teacher = conn.execute(
            """
            SELECT id, institution_id, password_hash, status
            FROM users
            WHERE teacher_id = %s
              AND institution_id = %s
            """,
            (data.teacher_id, requester[0])
        ).fetchone()

        if teacher is None:
            return {
                "message": "Teacher not found."
            }

        if teacher[3] != "active":
            return {
                "message": "Teacher account is not active."
            }

        if not password_hash.verify(
            data.password,
            teacher[2]
        ):
            return {
                "message": "Invalid Teacher ID or password."
            }

        existing_request = conn.execute(
            """
            SELECT id
            FROM approval_requests
            WHERE user_id = %s
              AND request_type = 'teacher_removal'
              AND status = 'pending'
            """,
            (teacher[0],)
        ).fetchone()

        if existing_request is not None:
            return {
                "message": "Teacher removal request is already pending."
            }

        conn.execute(
            """
            INSERT INTO approval_requests (
                institution_id,
                request_type,
                user_id,
                requested_by,
                status
            )
            VALUES (%s, 'teacher_removal', %s, %s, 'pending')
            """,
            (
                teacher[1],
                teacher[0],
                requester_id
            )
        )

        conn.commit()

        return {
            "message": "Teacher removal request sent to Admin!",
            "user_id": teacher[0],
            "teacher_id": data.teacher_id,
            "status": "pending"
        }

    finally:
        conn.close()


@router.post("/remove-director")
def request_director_removal(data: RemoveDirectorRequest, token: str):
    requester_id = get_current_user(token)

    conn = get_connection()

    try:
        requester = conn.execute(
            """
            SELECT institution_id
            FROM users
            WHERE id = %s
              AND status = 'active'
            """,
            (requester_id,)
        ).fetchone()

        if requester is None:
            return {
                "message": "Active user not found."
            }

        director = conn.execute(
            """
            SELECT id, institution_id, password_hash, status
            FROM users
            WHERE teacher_id = %s
              AND institution_id = %s
              AND designation = 'director'
            """,
            (data.director_id, requester[0])
        ).fetchone()

        if director is None:
            return {
                "message": "Director not found."
            }

        if director[3] != "active":
            return {
                "message": "Director account is not active."
            }

        if not password_hash.verify(
            data.password,
            director[2]
        ):
            return {
                "message": "Invalid Director ID or password."
            }

        existing_request = conn.execute(
            """
            SELECT id
            FROM approval_requests
            WHERE user_id = %s
              AND request_type = 'director_removal'
              AND status = 'pending'
            """,
            (director[0],)
        ).fetchone()

        if existing_request is not None:
            return {
                "message": "Director removal request is already pending."
            }

        conn.execute(
            """
            INSERT INTO approval_requests (
                institution_id,
                request_type,
                user_id,
                requested_by,
                status
            )
            VALUES (%s, 'director_removal', %s, %s, 'pending')
            """,
            (
                director[1],
                director[0],
                requester_id
            )
        )

        conn.commit()

        return {
            "message": "Director removal request sent to Admin!",
            "user_id": director[0],
            "director_id": data.director_id,
            "status": "pending"
        }

    finally:
        conn.close()


@router.post("/approve")
def approve_request(data: ApprovalRequest, token: str):
    admin_user_id = get_current_user(token)

    conn = get_connection()

    try:
        admin = conn.execute(
            """
            SELECT id
            FROM users
            WHERE id = %s
              AND is_admin = TRUE
              AND status = 'active'
            """,
            (admin_user_id,)
        ).fetchone()

        if admin is None:
            return {
                "message": "Only an active Admin can approve requests."
            }

        request = conn.execute(
            """
            SELECT id, user_id, status
            FROM approval_requests
            WHERE id = %s
              AND institution_id = (
                  SELECT institution_id
                  FROM users
                  WHERE id = %s
              )
              AND status = 'pending'
            """,
            (data.request_id, admin_user_id)
        ).fetchone()

        if request is None:
            return {
                "message": "Approval request not found."
            }

        if data.action == "approve":

            request_type = conn.execute(
                """
                SELECT request_type
                FROM approval_requests
                WHERE id = %s
                """,
                (data.request_id,)
            ).fetchone()[0]

            if request_type == "registration":

                conn.execute(
                    """
                    UPDATE users
                    SET status = 'active'
                    WHERE id = %s
                    """,
                    (request[1],)
                )

                conn.execute(
                    """
                    UPDATE approval_requests
                    SET status = 'approved',
                        reviewed_at = NOW()
                    WHERE id = %s
                    """,
                    (data.request_id,)
                )

                conn.commit()

                return {
                    "message": "Registration approved successfully!",
                    "user_id": request[1],
                    "status": "active"
                }

            if request_type == "teacher_removal":

                conn.execute(
                    """
                    UPDATE users
                    SET status = 'removed'
                    WHERE id = %s
                    """,
                    (request[1],)
                )

                conn.execute(
                    """
                    UPDATE approval_requests
                    SET status = 'approved',
                        reviewed_at = NOW()
                    WHERE id = %s
                    """,
                    (data.request_id,)
                )

                conn.commit()

                return {
                    "message": "Teacher removal approved successfully!",
                    "user_id": request[1],
                    "status": "removed"
                }

            if request_type == "director_removal":

                conn.execute(
                    """
                    UPDATE users
                    SET status = 'removed'
                    WHERE id = %s
                    """,
                    (request[1],)
                )

                conn.execute(
                    """
                    UPDATE approval_requests
                    SET status = 'approved',
                        reviewed_at = NOW()
                    WHERE id = %s
                    """,
                    (data.request_id,)
                )

                conn.commit()

                return {
                    "message": "Director removal approved successfully!",
                    "user_id": request[1],
                    "status": "removed"
                }

            return {
                "message": "Unknown request type."
            }

        if data.action == "reject":

            request_type = conn.execute(
                """
                SELECT request_type
                FROM approval_requests
                WHERE id = %s
                """,
                (data.request_id,)
            ).fetchone()[0]

            conn.execute(
                """
                UPDATE approval_requests
                SET status = 'rejected',
                    reviewed_at = NOW()
                WHERE id = %s
                """,
                (data.request_id,)
            )

            if request_type == "registration":

                conn.execute(
                    """
                    UPDATE users
                    SET status = 'rejected'
                    WHERE id = %s
                    """,
                    (request[1],)
                )

                conn.commit()

                return {
                    "message": "Registration request rejected.",
                    "user_id": request[1],
                    "status": "rejected"
                }

            if request_type == "teacher_removal":

                conn.commit()

                return {
                    "message": "Teacher removal request rejected.",
                    "user_id": request[1],
                    "status": "active"
                }

            if request_type == "director_removal":

                conn.commit()

                return {
                    "message": "Director removal request rejected.",
                    "user_id": request[1],
                    "status": "active"
                }

            conn.commit()

            return {
                "message": "Unknown request type."
            }

        return {
            "message": "Invalid action."
        }

    finally:
        conn.close()


@router.get("/approval-requests")
def get_approval_requests(token: str):
    admin_user_id = get_current_user(token)

    conn = get_connection()

    try:
        admin = conn.execute(
            """
            SELECT institution_id
            FROM users
            WHERE id = %s
              AND is_admin = TRUE
              AND status = 'active'
            """,
            (admin_user_id,)
        ).fetchone()

        if admin is None:
            return {
                "message": "Only an active Admin can view approval requests."
            }

        requests = conn.execute(
            """
            SELECT
                ar.id,
                ar.request_type,
                ar.user_id,
                u.teacher_id,
                u.first_name,
                u.last_name,
                u.designation,
                ar.status,
                ar.created_at
            FROM approval_requests ar
            JOIN users u
              ON u.id = ar.user_id
            WHERE ar.institution_id = %s
              AND ar.status = 'pending'
            ORDER BY ar.created_at ASC
            """,
            (admin[0],)
        ).fetchall()

        return {
            "requests": [
                {
                    "request_id": row[0],
                    "request_type": row[1],
                    "user_id": row[2],
                    "teacher_id": row[3],
                    "first_name": row[4],
                    "last_name": row[5],
                    "designation": row[6],
                    "status": row[7],
                    "created_at": row[8]
                }
                for row in requests
            ]
        }

    finally:
        conn.close()


@router.get("/directors")
def get_directors(token: str):
    current_user_id = get_current_user(token)

    conn = get_connection()

    try:
        current_user = conn.execute(
            """
            SELECT institution_id
            FROM users
            WHERE id = %s
              AND status = 'active'
            """,
            (current_user_id,)
        ).fetchone()

        if current_user is None:
            return {
                "message": "Active user not found."
            }

        directors = conn.execute(
            """
            SELECT
                id,
                teacher_id,
                first_name,
                last_name,
                designation,
                status,
                profile_pic,
                signature
            FROM users
            WHERE institution_id = %s
              AND designation = 'director'
              AND status = 'active'
            ORDER BY created_at ASC
            """,
            (current_user[0],)
        ).fetchall()

        return {
            "directors": [
                {
                    "user_id": row[0],
                    "director_id": row[1],
                    "first_name": row[2],
                    "last_name": row[3],
                    "designation": row[4],
                    "status": row[5],
                    "profile_pic": row[6],
                    "signature": row[7]
                }
                for row in directors
            ]
        }

    finally:
        conn.close()


@router.get("/teachers")
def get_teachers(token: str):
    current_user_id = get_current_user(token)

    conn = get_connection()

    try:
        current_user = conn.execute(
            """
            SELECT institution_id
            FROM users
            WHERE id = %s
              AND status = 'active'
            """,
            (current_user_id,)
        ).fetchone()

        if current_user is None:
            return {
                "message": "Active user not found."
            }

        teachers = conn.execute(
            """
            SELECT
                id,
                teacher_id,
                first_name,
                last_name,
                designation,
                status,
                profile_pic,
                signature
            FROM users
            WHERE institution_id = %s
              AND designation != 'director'
              AND status = 'active'
            ORDER BY created_at ASC
            """,
            (current_user[0],)
        ).fetchall()

        return {
            "teachers": [
                {
                    "user_id": row[0],
                    "teacher_id": row[1],
                    "first_name": row[2],
                    "last_name": row[3],
                    "designation": row[4],
                    "status": row[5],
                    "profile_pic": row[6],
                    "signature": row[7]
                }
                for row in teachers
            ]
        }

    finally:
        conn.close()
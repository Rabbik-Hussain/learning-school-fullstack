CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    teacher_id VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100),
profile_pic TEXT,
signature TEXT,
designation VARCHAR(30) NOT NULL,
status VARCHAR(20) NOT NULL DEFAULT 'pending',
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE institutions (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    institution_id BIGINT REFERENCES institutions(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE approval_requests (
    id BIGSERIAL PRIMARY KEY,
    institution_id BIGINT NOT NULL REFERENCES institutions(id),
    request_type VARCHAR(30) NOT NULL,
    user_id BIGINT REFERENCES users(id),
    requested_by BIGINT REFERENCES users(id),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ
);
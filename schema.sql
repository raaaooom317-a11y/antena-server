CREATE TABLE IF NOT EXISTS antena_devices (
    device_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    display_name VARCHAR(60) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS antena_auth_challenges (
    challenge_id UUID PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS antena_access_sessions (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS antena_link_requests (
    request_id UUID PRIMARY KEY,
    helper_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    receiver_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'rejected', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (helper_id <> receiver_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS antena_one_pending_link_request_per_pair
    ON antena_link_requests(helper_id, receiver_id)
    WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS antena_trusted_devices (
    owner_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    helper_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    auto_accept BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (owner_id, helper_id),
    CHECK (owner_id <> helper_id)
);

CREATE TABLE IF NOT EXISTS antena_assistance_requests (
    request_id UUID PRIMARY KEY,
    helper_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    receiver_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'rejected', 'expired', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (helper_id <> receiver_id)
);

CREATE INDEX IF NOT EXISTS antena_pending_assistance_requests_by_receiver
    ON antena_assistance_requests(receiver_id, created_at)
    WHERE status = 'pending';

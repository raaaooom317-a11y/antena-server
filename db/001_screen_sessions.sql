CREATE TABLE IF NOT EXISTS antena_screen_sessions (
    session_id UUID PRIMARY KEY,
    assistance_request_id UUID NOT NULL REFERENCES antena_assistance_requests(request_id) ON DELETE CASCADE,
    helper_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    receiver_id TEXT NOT NULL REFERENCES antena_devices(device_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'active', 'rejected', 'ended', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    ended_reason TEXT,
    CHECK (helper_id <> receiver_id)
);

CREATE INDEX IF NOT EXISTS antena_screen_sessions_by_helper
    ON antena_screen_sessions(helper_id, status, expires_at);

CREATE INDEX IF NOT EXISTS antena_screen_sessions_by_receiver
    ON antena_screen_sessions(receiver_id, status, expires_at);

CREATE TABLE IF NOT EXISTS chat_history (
    id SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    message TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Optional: индекс для ускорения выборки по session_id
CREATE INDEX IF NOT EXISTS idx_chat_history_session_id ON chat_history(session_id);

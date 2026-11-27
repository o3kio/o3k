ALTER TABLE bootstrap_state ADD COLUMN IF NOT EXISTS enrolled_agent_epochs TEXT NOT NULL DEFAULT '{}';
ALTER TABLE bootstrap_state ADD COLUMN IF NOT EXISTS revoked_agents TEXT NOT NULL DEFAULT '{}';

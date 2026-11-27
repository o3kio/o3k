ALTER TABLE bootstrap_state ADD COLUMN enrolled_agent_epochs TEXT NOT NULL DEFAULT '{}';
ALTER TABLE bootstrap_state ADD COLUMN revoked_agents TEXT NOT NULL DEFAULT '{}';

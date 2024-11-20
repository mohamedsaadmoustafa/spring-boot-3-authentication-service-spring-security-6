ALTER TABLE refresh_token
ADD CONSTRAINT token_format CHECK (length(token) >= 10);
ALTER TABLE user_roles
ADD CONSTRAINT user_role_unique UNIQUE (user_id, role_id);
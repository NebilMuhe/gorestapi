CREATE TABLE "users" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "username" STRING NOT NULL UNIQUE,
    "email" STRING NOT NULL UNIQUE,
    "password" STRING NOT NULL
);

CREATE TABLE "sessions" (
     "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     username STRING NOT NULL UNIQUE,
     refresh_token STRING NOT NULL,
     is_used BOOL NULL DEFAULT false
);

ALTER TABLE "sessions" ADD FOREIGN KEY ("username") REFERENCES "users" ("username");

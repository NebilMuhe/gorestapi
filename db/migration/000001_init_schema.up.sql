CREATE TABLE "users" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "username" STRING NOT NULL UNIQUE,
    "email" STRING NOT NULL UNIQUE,
    "password" STRING NOT NULL
);

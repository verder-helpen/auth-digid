DROP TABLE IF EXISTS "saml_session";
DROP TABLE IF EXISTS "idcontact_session";

CREATE TABLE "idcontact_session" (
  "id" SERIAL NOT NULL,
  "sessionid" text NOT NULL,
  "attributes" text NOT NULL,
  "continuation" text NOT NULL,
  "attr_url" text,
  "expiry" timestamp,
  PRIMARY KEY("id")
);

CREATE UNIQUE INDEX ON "idcontact_session" ("sessionid");

CREATE TABLE "saml_session" (
  "id" SERIAL NOT NULL,
  "sessionid" text NOT NULL,
  "attributes" text NOT NULL,
  "expiry" timestamp,
  "idcontact_session_id" integer REFERENCES "idcontact_session" ("id") ON DELETE SET NULL,
  "session_attributes" text,
  PRIMARY KEY("id")
);

CREATE UNIQUE INDEX ON "saml_session" ("sessionid");

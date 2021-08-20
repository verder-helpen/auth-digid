DROP TABLE IF EXISTS "saml_session";
DROP TABLE IF EXISTS "idcontact_session";

CREATE TABLE "saml_session" (
  "id" SERIAL NOT NULL,
  "sessionid" text NOT NULL,
  "logoutid" text NOT NULL,
  "attributes" text NOT NULL,
  "expiry" timestamp,
  PRIMARY KEY("id")
);

CREATE UNIQUE INDEX ON "saml_session" ("sessionid");
CREATE UNIQUE INDEX ON "saml_session" ("logoutid");

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

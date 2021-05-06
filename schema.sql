DROP TABLE IF EXISTS "saml_session";
DROP TABLE IF EXISTS "idcontact_session";

CREATE TABLE "saml_session" (
  "id" SERIAL NOT NULL,
  "sessionid" text NOT NULL,
  "attributes" text NOT NULL,
  PRIMARY KEY("id")
);

CREATE UNIQUE INDEX ON "saml_session" ("sessionid");

CREATE TABLE "idcontact_session" (
  "id" SERIAL NOT NULL,
  "sessionid" text NOT NULL,
  "attributes" text NOT NULL,
  "continuation" text NOT NULL,
  "attr_url" text,
  PRIMARY KEY("id")
);

CREATE UNIQUE INDEX ON "idcontact_session" ("sessionid");

CREATE TABLE "rentnerproxy"."legacy_feature_handoff_parts" (
	"domain" varchar(32) NOT NULL,
	"sequence" integer NOT NULL,
	"sha256" varchar(64) NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"iv" "bytea" NOT NULL,
	CONSTRAINT "legacy_feature_handoff_parts_domain_sequence_pk" PRIMARY KEY("domain","sequence"),
	CONSTRAINT "legacy_feature_handoff_parts_sequence_check" CHECK ("rentnerproxy"."legacy_feature_handoff_parts"."sequence" between 0 and 1023),
	CONSTRAINT "legacy_feature_handoff_parts_sha256_check" CHECK ("rentnerproxy"."legacy_feature_handoff_parts"."sha256" ~ '^[a-f0-9]{64}$'),
	CONSTRAINT "legacy_feature_handoff_parts_iv_check" CHECK (octet_length("rentnerproxy"."legacy_feature_handoff_parts"."iv") = 12)
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."legacy_feature_handoffs" (
	"domain" varchar(32) PRIMARY KEY NOT NULL,
	"installation_id" varchar(64) NOT NULL,
	"state" varchar(9) NOT NULL,
	"digest" varchar(64) NOT NULL,
	"part_count" integer NOT NULL,
	"exported_at" timestamp with time zone DEFAULT now() NOT NULL,
	"committed_at" timestamp with time zone,
	CONSTRAINT "legacy_feature_handoffs_domain_check" CHECK ("rentnerproxy"."legacy_feature_handoffs"."domain" in ('monitoring', 'docker-discovery', 'load-balancer', 'dns', 'oidc', 'crowdsec')),
	CONSTRAINT "legacy_feature_handoffs_state_check" CHECK ("rentnerproxy"."legacy_feature_handoffs"."state" in ('exported', 'committed')),
	CONSTRAINT "legacy_feature_handoffs_digest_check" CHECK ("rentnerproxy"."legacy_feature_handoffs"."digest" ~ '^[a-f0-9]{64}$'),
	CONSTRAINT "legacy_feature_handoffs_part_count_check" CHECK ("rentnerproxy"."legacy_feature_handoffs"."part_count" between 0 and 1024),
	CONSTRAINT "legacy_feature_handoffs_commit_check" CHECK (("rentnerproxy"."legacy_feature_handoffs"."state" = 'committed') = ("rentnerproxy"."legacy_feature_handoffs"."committed_at" is not null))
);
--> statement-breakpoint
ALTER TABLE "rentnerproxy"."legacy_feature_handoffs" ADD CONSTRAINT "legacy_feature_handoffs_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE no action ON UPDATE no action;
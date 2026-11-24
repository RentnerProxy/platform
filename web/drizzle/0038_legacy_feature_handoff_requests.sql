CREATE TABLE "rentnerproxy"."legacy_feature_handoff_requests" (
	"installation_id" varchar(64) NOT NULL,
	"actor" varchar(64) NOT NULL,
	"operation" varchar(6) NOT NULL,
	"idempotency_key" varchar(64) NOT NULL,
	"fingerprint" varchar(64) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "legacy_feature_handoff_requests_installation_id_actor_operation_idempotency_key_pk" PRIMARY KEY("installation_id","actor","operation","idempotency_key"),
	CONSTRAINT "legacy_feature_handoff_requests_operation_check" CHECK ("rentnerproxy"."legacy_feature_handoff_requests"."operation" in ('begin', 'commit')),
	CONSTRAINT "legacy_feature_handoff_requests_fingerprint_check" CHECK ("rentnerproxy"."legacy_feature_handoff_requests"."fingerprint" ~ '^[a-f0-9]{64}$')
);
--> statement-breakpoint
ALTER TABLE "rentnerproxy"."legacy_feature_handoff_requests" ADD CONSTRAINT "legacy_feature_handoff_requests_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "legacy_feature_handoff_requests_installation_time_idx" ON "rentnerproxy"."legacy_feature_handoff_requests" USING btree ("installation_id","created_at");
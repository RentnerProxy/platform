CREATE TABLE "rentnerproxy"."app_runtime_delegations" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"installation_id" varchar(64) NOT NULL,
	"generation" bigint NOT NULL,
	"session_id" uuid NOT NULL,
	"token_hash" varchar(64) NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_event_retention" (
	"installation_id" varchar(64) PRIMARY KEY NOT NULL,
	"floor" bigint DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_events" (
	"sequence" bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "rentnerproxy"."app_runtime_events_sequence_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"id" uuid DEFAULT uuidv7() NOT NULL,
	"installation_id" varchar(64) NOT NULL,
	"type" varchar(64) NOT NULL,
	"capability_id" varchar(64) NOT NULL,
	"scope" varchar(32) NOT NULL,
	"resource_id" varchar(64) NOT NULL,
	"revision" varchar(64),
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"payload" jsonb,
	CONSTRAINT "app_runtime_events_id_unique" UNIQUE("id")
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_generations" (
	"installation_id" varchar(64) NOT NULL,
	"generation" bigint NOT NULL,
	"state" varchar(10) NOT NULL,
	"lease_expires_at" timestamp with time zone NOT NULL,
	"capabilities" jsonb NOT NULL,
	"permission_keys" jsonb NOT NULL,
	"has_ui" boolean DEFAULT false NOT NULL,
	CONSTRAINT "app_runtime_generations_installation_id_generation_pk" PRIMARY KEY("installation_id","generation"),
	CONSTRAINT "app_runtime_generations_number_check" CHECK ("rentnerproxy"."app_runtime_generations"."generation" between 1 and 9007199254740991),
	CONSTRAINT "app_runtime_generations_state_check" CHECK ("rentnerproxy"."app_runtime_generations"."state" in ('preparing', 'active', 'revoked'))
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_grants" (
	"installation_id" varchar(64) NOT NULL,
	"capability_id" varchar(64) NOT NULL,
	"scope" varchar(32) NOT NULL,
	"resource_id" varchar(64) NOT NULL,
	"allow_service" boolean DEFAULT false NOT NULL,
	"permission_key" varchar(32),
	CONSTRAINT "app_runtime_grants_installation_id_capability_id_scope_resource_id_pk" PRIMARY KEY("installation_id","capability_id","scope","resource_id")
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_installations" (
	"id" varchar(64) PRIMARY KEY NOT NULL,
	"app_id" varchar(97) NOT NULL,
	"uid" bigint NOT NULL,
	"authorization_epoch" bigint DEFAULT 0 NOT NULL,
	CONSTRAINT "app_runtime_installations_uid_check" CHECK ("rentnerproxy"."app_runtime_installations"."uid" between 20000 and 59999)
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_messages" (
	"installation_id" varchar(64) NOT NULL,
	"actor" varchar(64) NOT NULL,
	"kind" varchar(16) NOT NULL,
	"idempotency_key" varchar(64) NOT NULL,
	"fingerprint" varchar(64) NOT NULL,
	"generation" bigint NOT NULL,
	"payload" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "app_runtime_messages_installation_id_actor_kind_idempotency_key_pk" PRIMARY KEY("installation_id","actor","kind","idempotency_key")
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_operation_requests" (
	"installation_id" varchar(64) NOT NULL,
	"key_hash" varchar(64) NOT NULL,
	"payload_hash" varchar(64) NOT NULL,
	"operation_id" uuid NOT NULL,
	CONSTRAINT "app_runtime_operation_requests_installation_id_key_hash_pk" PRIMARY KEY("installation_id","key_hash")
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_operations" (
	"id" uuid PRIMARY KEY NOT NULL,
	"installation_id" varchar(64) NOT NULL,
	"generation" bigint NOT NULL,
	"delegation_id" uuid,
	"actor_user_id" uuid,
	"request_id" varchar(64) NOT NULL,
	"status" varchar(16) NOT NULL,
	"input" jsonb NOT NULL,
	"result" jsonb,
	"failure" jsonb,
	"lease_token" uuid,
	"lease_expires_at" timestamp with time zone,
	"started_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "app_runtime_operations_state_check" CHECK ("rentnerproxy"."app_runtime_operations"."status" in ('accepted', 'running', 'cancelled', 'succeeded', 'failed') and
                ("rentnerproxy"."app_runtime_operations"."status" = 'failed') = ("rentnerproxy"."app_runtime_operations"."failure" is not null) and
                ("rentnerproxy"."app_runtime_operations"."status" = 'running' or "rentnerproxy"."app_runtime_operations"."lease_token" is null) and
                ("rentnerproxy"."app_runtime_operations"."lease_token" is null) = ("rentnerproxy"."app_runtime_operations"."lease_expires_at" is null))
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_owned_proxy_hosts" (
	"installation_id" varchar(64) NOT NULL,
	"host_id" varchar(64) NOT NULL,
	"proxy_host_id" uuid NOT NULL,
	CONSTRAINT "app_runtime_owned_proxy_hosts_installation_id_host_id_pk" PRIMARY KEY("installation_id","host_id"),
	CONSTRAINT "app_runtime_owned_proxy_hosts_proxy_host_id_unique" UNIQUE("proxy_host_id")
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_role_permissions" (
	"installation_id" varchar(64) NOT NULL,
	"role_id" uuid NOT NULL,
	"key" varchar(32) NOT NULL,
	CONSTRAINT "app_runtime_role_permissions_installation_id_role_id_key_pk" PRIMARY KEY("installation_id","role_id","key")
);
--> statement-breakpoint
CREATE TABLE "rentnerproxy"."app_runtime_secrets" (
	"installation_id" varchar(64) NOT NULL,
	"id" varchar(64) NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"iv" "bytea" NOT NULL,
	CONSTRAINT "app_runtime_secrets_installation_id_id_pk" PRIMARY KEY("installation_id","id"),
	CONSTRAINT "app_runtime_secrets_iv_check" CHECK (octet_length("rentnerproxy"."app_runtime_secrets"."iv") = 12)
);
--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_delegations" ADD CONSTRAINT "app_runtime_delegations_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "rentnerproxy"."sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_delegations" ADD CONSTRAINT "app_runtime_delegations_installation_id_generation_app_runtime_generations_installation_id_generation_fk" FOREIGN KEY ("installation_id","generation") REFERENCES "rentnerproxy"."app_runtime_generations"("installation_id","generation") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_event_retention" ADD CONSTRAINT "app_runtime_event_retention_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_events" ADD CONSTRAINT "app_runtime_events_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_generations" ADD CONSTRAINT "app_runtime_generations_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_grants" ADD CONSTRAINT "app_runtime_grants_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_messages" ADD CONSTRAINT "app_runtime_messages_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_operation_requests" ADD CONSTRAINT "app_runtime_operation_requests_operation_id_app_runtime_operations_id_fk" FOREIGN KEY ("operation_id") REFERENCES "rentnerproxy"."app_runtime_operations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_operations" ADD CONSTRAINT "app_runtime_operations_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_owned_proxy_hosts" ADD CONSTRAINT "app_runtime_owned_proxy_hosts_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_owned_proxy_hosts" ADD CONSTRAINT "app_runtime_owned_proxy_hosts_proxy_host_id_proxy_hosts_id_fk" FOREIGN KEY ("proxy_host_id") REFERENCES "rentnerproxy"."proxy_hosts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_role_permissions" ADD CONSTRAINT "app_runtime_role_permissions_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_role_permissions" ADD CONSTRAINT "app_runtime_role_permissions_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "rentnerproxy"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rentnerproxy"."app_runtime_secrets" ADD CONSTRAINT "app_runtime_secrets_installation_id_app_runtime_installations_id_fk" FOREIGN KEY ("installation_id") REFERENCES "rentnerproxy"."app_runtime_installations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "app_runtime_delegations_hash_idx" ON "rentnerproxy"."app_runtime_delegations" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "app_runtime_delegations_session_idx" ON "rentnerproxy"."app_runtime_delegations" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "app_runtime_delegations_expiry_idx" ON "rentnerproxy"."app_runtime_delegations" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "app_runtime_events_installation_sequence_idx" ON "rentnerproxy"."app_runtime_events" USING btree ("installation_id","sequence");--> statement-breakpoint
CREATE INDEX "app_runtime_events_installation_time_idx" ON "rentnerproxy"."app_runtime_events" USING btree ("installation_id","occurred_at");--> statement-breakpoint
CREATE UNIQUE INDEX "app_runtime_generations_one_active_idx" ON "rentnerproxy"."app_runtime_generations" USING btree ("installation_id") WHERE "rentnerproxy"."app_runtime_generations"."state" = 'active';--> statement-breakpoint
CREATE UNIQUE INDEX "app_runtime_installations_uid_idx" ON "rentnerproxy"."app_runtime_installations" USING btree ("uid");--> statement-breakpoint
CREATE INDEX "app_runtime_messages_installation_time_idx" ON "rentnerproxy"."app_runtime_messages" USING btree ("installation_id","created_at");--> statement-breakpoint
CREATE INDEX "app_runtime_operation_requests_operation_idx" ON "rentnerproxy"."app_runtime_operation_requests" USING btree ("operation_id");--> statement-breakpoint
CREATE INDEX "app_runtime_operations_pending_idx" ON "rentnerproxy"."app_runtime_operations" USING btree ("status","created_at","id") WHERE "rentnerproxy"."app_runtime_operations"."status" in ('accepted', 'running');--> statement-breakpoint
CREATE INDEX "app_runtime_operations_installation_pending_idx" ON "rentnerproxy"."app_runtime_operations" USING btree ("installation_id") WHERE "rentnerproxy"."app_runtime_operations"."status" in ('accepted', 'running');--> statement-breakpoint
CREATE INDEX "app_runtime_role_permissions_role_idx" ON "rentnerproxy"."app_runtime_role_permissions" USING btree ("role_id");
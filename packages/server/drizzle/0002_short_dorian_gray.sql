CREATE TABLE "auth_logs " (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"browser" varchar(255) NOT NULL,
	"ip_address" varchar(255) NOT NULL,
	"device_type" varchar(255),
	"device_os" varchar(255),
	"country" varchar(255),
	"date" varchar(50),
	"is_bot" boolean DEFAULT false NOT NULL,
	"is_tunnel" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "auth_logs " ADD CONSTRAINT "auth_logs _user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;
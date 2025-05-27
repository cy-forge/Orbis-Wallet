import { pgTable, integer, varchar, jsonb, timestamp, primaryKey, boolean, uuid } from 'drizzle-orm/pg-core';

// users table
export const usersTable = pgTable('users', {
    id: uuid('id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 255 }).notNull().unique(),
    password: varchar('password', { length: 255 }).notNull(),
    mfaEnabled: boolean('mfa_enabled').notNull().default(false),
    mfaSecret: varchar('mfa_secret', { length: 255 }),
    role: varchar('role', { length: 50 }).notNull().default('user'),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// roles table
export const rolesTable = pgTable('roles', {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 255 }).notNull().unique(),
    permissions: jsonb('permissions').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// sessions table
export const sessionsTable = pgTable('sessions', {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'cascade' }),
    token: varchar('token', { length: 255 }).notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

export const rolesToUsersTable = pgTable('roles_users', {
    roleId: uuid('role_id').notNull().references(() => rolesTable.id),
    userId: uuid('user_id').notNull().references(() => usersTable.id),
}, (t) => [
    primaryKey({ columns: [t.roleId, t.userId] }),
]);

// auth_logs table
export const authLogsTable  = pgTable('auth_logs ', {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').notNull().references(() => usersTable.id),
    browser: varchar('browser', { length: 255 }).notNull(),
    ipAddress: varchar('ip_address', { length: 255 }).notNull(),
    deviceType: varchar('device_type', { length: 255 }),
    deviceOs: varchar('device_os', { length: 255 }),
    country : varchar('country', { length: 255 }),
    date: varchar('date', { length: 50 }),
    isBot: boolean('is_bot').notNull().default(false),
    isTunnel: boolean('is_tunnel').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});
  
// categories Table
export const categoriesTable = pgTable('categories', {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 255 }).notNull().unique(),
    slug: varchar('slug', { length: 255 }).notNull().unique(),
    status: varchar('status', { length: 50 }).notNull().default('active'),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

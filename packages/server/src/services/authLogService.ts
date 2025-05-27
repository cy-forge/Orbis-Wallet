import { db } from "../utils/db";
import { usersTable } from "../db/schema";
import { authLogsTable } from '../db/schema';
import { pgTable, uuid, varchar, boolean, timestamp } from 'drizzle-orm/pg-core';
import { eq } from 'drizzle-orm';

export const logAuthAttempt = async (userId: string, browser: string, ipAddress: string, deviceType: string, deviceOS: string, country: string, date: string, isBot: boolean, isTunnel: boolean) => {
    const authLog = {
        userId,
        browser,
        ipAddress,
        deviceType,
        deviceOS,
        country,
        date,
        isBot,
        isTunnel
    };

    try {
        const result = await db.insert(authLogsTable).values(authLog);
        return result;
    } catch (error) {
        console.error('Error logging auth attempt:', error);
        throw new Error('Failed to log auth attempt');
    }
}

export const getAuthLogs = async (userId: string, limit: number, offset: number) => {
    try {
        const logs = await db
            .select()
            .from(authLogsTable)
            .where(eq(authLogsTable.userId, userId))
            .limit(limit)
            .offset(offset);
        return logs;
    } catch (error) {
        console.error('Error fetching auth logs:', error);
        throw new Error('Failed to fetch auth logs');
    }
}

export const getAuthLogById = async (logId: string) => {
    try {
        const log = await db.select().from(authLogsTable).where(eq(authLogsTable.id, logId));
        return log;
    } catch (error) {
        console.error('Error fetching auth log by ID:', error);
        throw new Error('Failed to fetch auth log by ID');
    }
}

export const deleteAuthLog = async (logId: string) => {
    try {
        const result = await db.delete(authLogsTable).where(eq(authLogsTable.id, logId));
        return result;
    } catch (error) {
        console.error('Error deleting auth log:', error);
        throw new Error('Failed to delete auth log');
    }
}

export const updateAuthLog = async (logId: string, updateData: Partial<typeof authLogsTable>) => {
    try {
        const result = await db.update(authLogsTable).set(updateData).where(eq(authLogsTable.id, logId));
        return result;
    } catch (error) {
        console.error('Error updating auth log:', error);
        throw new Error('Failed to update auth log');
    }
}

export const getAuthLogsByDate = async (userId: string, date: string, limit: number, offset: number) => {
    try {
        const logs = await db
            .select()
            .from(authLogsTable)
            .where(eq(authLogsTable.date, date))
            .limit(limit)
            .offset(offset);
        return logs;
    } catch (error) {
        console.error('Error fetching auth logs by date with pagination:', error);
        throw new Error('Failed to fetch auth logs by date with pagination');
    }
}
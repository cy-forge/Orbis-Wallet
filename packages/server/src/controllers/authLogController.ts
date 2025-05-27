import { Hono } from "hono";
import { lookup as geoipLookup } from "fast-geoip";
import { isbot } from 'isbot';
import { logAuthAttempt, getAuthLogs, getAuthLogById, deleteAuthLog, updateAuthLog, getAuthLogsByDate} from "../services/authLogService";
import { rbacAdminMiddleware } from "../middlewares/rbacMiddleware";
import { isAuthenticated } from "../middlewares/authMiddleware";



const authLogController = new Hono();

authLogController.post("/auth-log", isAuthenticated, async (c) => {
    try {
        const { userId, browser, ipAddress, deviceType, deviceOS, date } = await c.req.json();

        if (!userId || !browser || !ipAddress || !deviceType || !deviceOS || !date) {
            return c.json({ error: "All fields are required" }, 400);
        }

        // Extract IP address from headers
        const clientIp = c.req.header("x-forwarded-for") || c.req.header("remote-addr") || ipAddress;

        // Get country
        const country = await geoipLookup(clientIp)
        .then((geo) => {
            if (geo) {
                return geo.country;
            } else {
                return "Unknown";
            }
        })
        .catch((error) => {
            console.error("Error fetching geo data:", error);
            return "Unknown";
        });


        const userAgent = c.req.header('user-agent');
        const isRequestBot = isbot(userAgent);
        let isTunnel = false;

        const forwardedFor = c.req.header('x-forwarded-for');
        if (forwardedFor) {
            const ips = forwardedFor.split(',').map(ip => ip.trim());
            // var clientIp;

            if (ips.length > 1) {
                isTunnel = true;
            }
        }

        await logAuthAttempt(userId, browser, ipAddress, deviceType, deviceOS, country, date, isRequestBot, isTunnel);

        return c.json({ message: "Auth log created successfully" }, 201);
    }
    catch (error) {
        console.error("Error creating auth log:", error);
        return c.json({ error: "Failed to create auth log" }, 500);
    }
});

authLogController.get("/auth-logs", rbacAdminMiddleware, async (c) => {
    try {
        const { userId, limit = 10, offset = 0 } = c.req.query();

        if (!userId) {
            return c.json({ error: "User ID is required" }, 400);
        }

        const logs = await getAuthLogs(userId, Number(limit), Number(offset));

        return c.json({ logs }, 200);
    }
    catch (error) {
        console.error("Error fetching auth logs:", error);
        return c.json({ error: "Failed to fetch auth logs" }, 500);
    }
});

authLogController.get("/auth-log/:logId", rbacAdminMiddleware, async (c) => {
    try {
        const { logId } = c.req.param();

        if (!logId) {
            return c.json({ error: "Log ID is required" }, 400);
        }

        const log = await getAuthLogById(logId);

        if (!log) {
            return c.json({ error: "Auth log not found" }, 404);
        }

        return c.json({ log }, 200);
    }
    catch (error) {
        console.error("Error fetching auth log by ID:", error);
        return c.json({ error: "Failed to fetch auth log by ID" }, 500);
    }
});

authLogController.delete("/auth-log/:logId", rbacAdminMiddleware, async (c) => {
    try {
        const { logId } = c.req.param();

        if (!logId) {
            return c.json({ error: "Log ID is required" }, 400);
        }

        await deleteAuthLog(logId);

        return c.json({ message: "Auth log deleted successfully" }, 200);
    }
    catch (error) {
        console.error("Error deleting auth log:", error);
        return c.json({ error: "Failed to delete auth log" }, 500);
    }
});

authLogController.patch("/auth-log/:logId", rbacAdminMiddleware, async (c) => {
    try {
        const { logId } = c.req.param();
        const updateData = await c.req.json();

        if (!logId) {
            return c.json({ error: "Log ID is required" }, 400);
        }

        await updateAuthLog(logId, updateData);

        return c.json({ message: "Auth log updated successfully" }, 200);
    }
    catch (error) {
        console.error("Error updating auth log:", error);
        return c.json({ error: "Failed to update auth log" }, 500);
    }
});

authLogController.get("/auth-logs/date", rbacAdminMiddleware, async (c) => {
    try {
        const { userId, date, limit = 10, offset = 0 } = c.req.query();

        if (!userId || !date) {
            return c.json({ error: "User ID and date are required" }, 400);
        }

        const logs = await getAuthLogsByDate(userId, date, Number(limit), Number(offset));

        return c.json({ logs }, 200);
    }
    catch (error) {
        console.error("Error fetching auth logs by date:", error);
        return c.json({ error: "Failed to fetch auth logs by date" }, 500);
    }
});
export default authLogController;

import app from "../index";
import { describe, it, expect, mock } from 'bun:test';
import { Hono, Env } from 'hono';
import { createMiddleware } from 'hono/factory';
// import { createRoute } from 'hono/routing';
import { hc } from 'hono/client';


// Import the controller code
import authLogController from '../../server/src/controllers/authLogController'; // **Adjust t

// Mock external dependencies
jest.mock('fast-geoip', () => ({
  lookup: jest.fn(),
}));
jest.mock('isbot', () => ({
  isbot: jest.fn(),
}));
jest.mock('../services/authLogService', () => ({
  logAuthAttempt: jest.fn(),
  getAuthLogs: jest.fn(),
  getAuthLogById: jest.fn(),
  deleteAuthLog: jest.fn(),
  updateAuthLog: jest.fn(),
  getAuthLogsByDate: jest.fn(),
}));

// Import the mocked modules after mocking
import { lookup as geoipLookup } from 'fast-geoip';
import { isbot } from 'isbot';
import { logAuthAttempt } from '../src/services/authLogService';

// Mock the isAuthenticated middleware for testing purposes
// In a real scenario, you might want a more sophisticated mock
const isAuthenticated = createMiddleware(async (c, next) => {
  // Simulate an authenticated user
  // You might add a user object to c.req.user for more complex tests
  await next();
});

// Create a test Hono app and mount the controller
// const app = new Hono<Env>()
//   .use(isAuthenticated as any) // Apply the mock middleware
//   .route('/', authLogController); // Mount the controller

// Create a Hono client for testing
// const client = hc(app.fetch as any); // Use app.fetch as the handler for the client
// const client = hc(app.fetch as any); // Use app.fetch as the handler for the client
// const client = hc(app.fetch as any, {
//   url: 'http://localhost', // Base URL for the client
//   headers: {
//     'Content-Type': 'application/json', // Default headers
//   },
// });

describe('Auth Log Controller', () => {
  // Reset mocks before each test
  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe('POST /auth-log', () => {
    const validAuthLogData = {
      userId: 'user123',
      browser: 'Chrome',
      ipAddress: '192.168.1.100',
      deviceType: 'Desktop',
      deviceOS: 'Windows',
      date: new Date().toISOString(),
    };

    it('should successfully create an auth log with all valid fields', async () => {
      // Mock successful geoip lookup
      (geoipLookup as jest.Mock).mockResolvedValue({ country: 'US' });
      // Mock isbot
      (isbot as jest.Mock).mockReturnValue(false);
      // Mock successful logAuthAttempt
      (logAuthAttempt as jest.Mock).mockResolvedValue(undefined);

      const response = await client['/auth-log'].$url.call .$post({ json: validAuthLogData });
      const body = await response.json();

      expect(response.status).toBe(201);
      expect(body).toEqual({ message: 'Auth log created successfully' });

      // Verify that logAuthAttempt was called with the correct arguments
      expect(logAuthAttempt).toHaveBeenCalledWith(
        validAuthLogData.userId,
        validAuthLogData.browser,
        validAuthLogData.ipAddress,
        validAuthLogData.deviceType,
        validAuthLogData.deviceOS,
        'US', // Expected country from mock
        validAuthLogData.date,
        false, // Expected isBot from mock
        false // Expected isTunnel
      );
    });

    it('should return 400 if any required field is missing', async () => {
      const incompleteData = {
        userId: 'user123',
        browser: 'Chrome',
        // ipAddress is missing
        deviceType: 'Desktop',
        deviceOS: 'Windows',
        date: new Date().toISOString(),
      };

      const response = await client.authLog.$post({ json: incompleteData });
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body).toEqual({ error: 'All fields are required' });
      expect(logAuthAttempt).not.toHaveBeenCalled();
    });

    it('should use x-forwarded-for header for IP if present and detect tunnel', async () => {
      (geoipLookup as jest.Mock).mockResolvedValue({ country: 'CA' });
      (isbot as jest.Mock).mockReturnValue(false);
      (logAuthAttempt as jest.Mock).mockResolvedValue(undefined);

      const dataWithForwardedFor = {
        ...validAuthLogData,
        ipAddress: '10.0.0.1', // This should be ignored
      };

      const response = await client.authLog.$post({
        json: dataWithForwardedFor,
        headers: {
          'x-forwarded-for': '203.0.113.1, 198.51.100.10',
        },
      });

      expect(response.status).toBe(201);
      expect(logAuthAttempt).toHaveBeenCalledWith(
        validAuthLogData.userId,
        validAuthLogData.browser,
        '203.0.113.1', // Expect the first IP from x-forwarded-for
        validAuthLogData.deviceType,
        validAuthLogData.deviceOS,
        'CA',
        validAuthLogData.date,
        false,
        true // Expect isTunnel to be true
      );
      expect(geoipLookup).toHaveBeenCalledWith('203.0.113.1');
    });

    it('should use remote-addr header for IP if x-forwarded-for is not present', async () => {
      (geoipLookup as jest.Mock).mockResolvedValue({ country: 'DE' });
      (isbot as jest.Mock).mockReturnValue(false);
      (logAuthAttempt as jest.Mock).mockResolvedValue(undefined);

      const dataWithRemoteAddr = {
        ...validAuthLogData,
        ipAddress: '10.0.0.1', // This should be ignored
      };

      const response = await client.authLog.$post({
        json: dataWithRemoteAddr,
        headers: {
          'remote-addr': '172.16.0.5',
        },
      });

      expect(response.status).toBe(201);
      expect(logAuthAttempt).toHaveBeenCalledWith(
        validAuthLogData.userId,
        validAuthLogData.browser,
        '172.16.0.5', // Expect remote-addr IP
        validAuthLogData.deviceType,
        validAuthLogData.deviceOS,
        'DE',
        validAuthLogData.date,
        false,
        false // Expect isTunnel to be false
      );
      expect(geoipLookup).toHaveBeenCalledWith('172.16.0.5');
    });

    it('should use the ipAddress from the body if no relevant headers are present', async () => {
      (geoipLookup as jest.Mock).mockResolvedValue({ country: 'JP' });
      (isbot as jest.Mock).mockReturnValue(false);
      (logAuthAttempt as jest.Mock).mockResolvedValue(undefined);

      const response = await client.authLog.$post({
        json: validAuthLogData,
        headers: {
          // No x-forwarded-for or remote-addr
        },
      });

      expect(response.status).toBe(201);
      expect(logAuthAttempt).toHaveBeenCalledWith(
        validAuthLogData.userId,
        validAuthLogData.browser,
        validAuthLogData.ipAddress, // Expect body IP
        validAuthLogData.deviceType,
        validAuthLogData.deviceOS,
        'JP',
        validAuthLogData.date,
        false,
        false
      );
      expect(geoipLookup).toHaveBeenCalledWith(validAuthLogData.ipAddress);
    });


    it('should handle geoipLookup returning null and set country to Unknown', async () => {
      (geoipLookup as jest.Mock).mockResolvedValue(null); // Simulate geoip returning null
      (isbot as jest.Mock).mockReturnValue(false);
      (logAuthAttempt as jest.Mock).mockResolvedValue(undefined);

      const response = await client.authLog.$post({ json: validAuthLogData });
      const body = await response.json();

      expect(response.status).toBe(201);
      expect(body).toEqual({ message: 'Auth log created successfully' });

      expect(logAuthAttempt).toHaveBeenCalledWith(
        validAuthLogData.userId,
        validAuthLogData.browser,
        validAuthLogData.ipAddress,
        validAuthLogData.deviceType,
        validAuthLogData.deviceOS,
        'Unknown', // Expect country to be Unknown
        validAuthLogData.date,
        false,
        false
      );
    });

    it('should handle geoipLookup throwing an error and set country to Unknown', async () => {
      (geoipLookup as jest.Mock).mockRejectedValue(new Error('GeoIP Error')); // Simulate geoip error
      (isbot as jest.Mock).mockReturnValue(false);
      (logAuthAttempt as jest.Mock).mockResolvedValue(undefined);

      // Mock console.error to prevent test output clutter and potentially assert on it
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      const response = await client.authLog.$post({ json: validAuthLogData });
      const body = await response.json();

      expect(response.status).toBe(201);
      expect(body).toEqual({ message: 'Auth log created successfully' });

      expect(logAuthAttempt).toHaveBeenCalledWith(
        validAuthLogData.userId,
        validAuthLogData.browser,
        validAuthLogData.ipAddress,
        validAuthLogData.deviceType,
        validAuthLogData.deviceOS,
        'Unknown', // Expect country to be Unknown
        validAuthLogData.date,
        false,
        false
      );
      expect(consoleErrorSpy).toHaveBeenCalledWith('Error fetching geo data:', expect.any(Error));

      consoleErrorSpy.mockRestore(); // Restore original console.error
    });


    it('should detect if the request is from a bot', async () => {
      (geoipLookup as jest.Mock).mockResolvedValue({ country: 'US' });
      (isbot as jest.Mock).mockReturnValue(true); // Simulate request from a bot
      (logAuthAttempt as jest.Mock).mockResolvedValue(undefined);

      const response = await client.authLog.$post({
        json: validAuthLogData,
        headers: {
          'user-agent': 'SomeBotCrawler/1.0',
        },
      });

      expect(response.status).toBe(201);
      expect(logAuthAttempt).toHaveBeenCalledWith(
        validAuthLogData.userId,
        validAuthLogData.browser,
        validAuthLogData.ipAddress,
        validAuthLogData.deviceType,
        validAuthLogData.deviceOS,
        'US',
        validAuthLogData.date,
        true, // Expect isBot to be true
        false
      );
      expect(isbot).toHaveBeenCalledWith('SomeBotCrawler/1.0');
    });

    it('should return 500 if logAuthAttempt service fails', async () => {
      (geoipLookup as jest.Mock).mockResolvedValue({ country: 'US' });
      (isbot as jest.Mock).mockReturnValue(false);
      // Simulate logAuthAttempt throwing an error
      (logAuthAttempt as jest.Mock).mockRejectedValue(new Error('Database Error'));

      // Mock console.error
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      const response = await client.authLog.$post({ json: validAuthLogData });
      const body = await response.json();

      expect(response.status).toBe(500);
      expect(body).toEqual({ error: 'Failed to create auth log' });
      expect(consoleErrorSpy).toHaveBeenCalledWith('Error creating auth log:', expect.any(Error));

      consoleErrorSpy.mockRestore(); // Restore original console.error
    });
  });

});



///////////////////////////////////////////////////////////////////////////////////////////////////////

// import app from "../index";
// import { describe, it, expect, beforeAll, afterAll } from "bun:test";
// import { authLogsTable, usersTable } from "../src/db/schema";
// import { db } from "../src/utils/db"; // Your database connection
// import * as jwt from 'jsonwebtoken';
// import * as dotenv from 'dotenv';
// import { uuid } from "drizzle-orm/gel-core";


// dotenv.config();

// if (!process.env.JWT_SECRET) {
//     console.error(' JWT_SECRET environment variable is not defined');
//     process.env.JWT_SECRET = 'test-secret-for-testing-only';
//     console.warn('⚠ Using fallback test secret');
//     }

//     const generateToken = (uid: string, role: string = 'admin') => {
//       try {
//           const token = jwt.sign(
//           { id: uid, email: 'test@example.com', role },
//           process.env.JWT_SECRET!,
//           { expiresIn: '1h' }
//           );
//           console.log(` Generated ${role} token successfully`);
//           return token;
//       } catch (error) {
//           console.error(' Failed to generate token:', error);
//           throw error;
//       }
//     };


// describe("AuthLogController", () => {
//   // Create a test user in the database before running tests
//     // Ensure the user ID is unique for each test run
//     const uniqueId = () => {
//       const randomId = uuid();
//       return randomId;
//     };
//     const userId = uniqueId().toString();
//     const adminId = uniqueId().toString();
//     const logId = uniqueId().toString();

//     beforeAll(async () => {
//       await db.insert(usersTable).values({
//         id: userId,
//         email: "test@example.com",
//         password: "hashed-password", // Use a hashed password if your schema requires
//         role: "user",
//       });
//       console.log(' Test user created with ID:', userId);

//       await db.insert(usersTable).values({
//         id: adminId,
//         email: "admin@example.com",
//         password: "hashed-password", // Use a hashed password if your schema requires
//         role: "admin",
//       });
//       console.log(' Test admin user created with ID:', adminId);
//     });

//     // Clean up test user after tests
//     afterAll(async () => {
//       await db.delete(usersTable);
//     });

//   const adminToken = generateToken(adminId, 'admin');
//   const userToken = generateToken(userId, 'user');
//   beforeAll(async () => {
//     // Set up database or mock data if needed
//     await db.insert(authLogsTable).values({
//       id: logId,
//       userId: userId,
//       browser: "Chrome",
//       ipAddress: "127.0.0.1",
//       deviceType: "Desktop",
//       deviceOs: "Windows",
//       country: "US",
//       date: "2025-05-05",
//       isBot: false,
//       isTunnel: false,
//     });
//   });

//   afterAll(async () => {
//     // Clean up database
//     await db.delete(authLogsTable);
//   });

//   it("should create an auth log", async () => {
//     const response = await app.request("/auth-log", {
//       method: "POST",
//       headers: {
//         "Content-Type": "application/json",
//         Authorization: `Bearer ${userToken}`, // Mock a valid token
//       },
//       body: JSON.stringify({
//         userId: userId,
//         browser: "Firefox",
//         ipAddress: "192.168.24.27",
//         deviceType: "Mobile",
//         deviceOS: "Android",
//         date: "2025-05-05",
//       }),
//     });
//     expect(response.status).toBe(201);
//     const body = await response.json();
//     expect(body.message).toBe("Auth log created successfully");
//   });

//   it("should fetch auth logs", async () => {
//     const params = new URLSearchParams({
//       userId: userId,
//       limit: "10",
//       offset: "0",
//     }).toString();
//     const response = await app.request(`/auth-logs?${params}`, {
//       method: "GET",
//       headers: {
//         Authorization: `Bearer ${adminToken}`, // Mock a valid token
//       },
//     });
//     expect(response.status).toBe(200);
//     const body = await response.json();
//     expect(body.logs).toBeDefined();
//     expect(body.logs.length).toBeGreaterThan(0);
//   });

  
//   it("should fetch auth log by ID", async () => {
//     const response = await app.request(`/auth-log/${logId}`, {
//       method: "GET",
//       headers: {
//         Authorization: `Bearer ${adminToken}`,
//       },
//     });
//     expect(response.status).toBe(200);
//     const body = await response.json();
//     // expect(body.log).toBeDefined();
//     expect(body.log.id).toBe(logId);
//   });
    

//   //   expect(response.status).toBe(200);
//   //   expect(response.body.logs).toBeDefined();
//   //   expect(response.body.logs.length).toBeGreaterThan(0);
//   // });

//   it("should return 403 for unauthorized access", async () => {
//     const response = await app.request("/auth-logs", {
//       method: "GET",
//       headers: {
//         Authorization: `Bearer ${userToken}`,
//       },
//     });

//     expect(response.status).toBe(403);
//     const body = await response.json();
//     expect(body.error).toBe("Access Denied");
//   });
// });
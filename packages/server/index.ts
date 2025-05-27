import { Hono } from "hono";
import { rbacAdminMiddleware } from "./src/middlewares/rbacMiddleware";
import { cors } from 'hono/cors'
import authController from "./src/controllers/authController";
import categoryController from './src/controllers/categoryController';
import authLogController from "./src/controllers/authLogController";
import { initializeDB } from "./src/utils/db";
import userController from "./src/controllers/userController";

const app = new Hono();

// Initialize database
initializeDB();

app.use('*', cors());

/**
 * Utilize the relevant middlewares in each request definition
 * Example: app.get('/api/get-tokens', userMiddleware, controller) where userMiddleware can
 * be defined using `createRbacMiddleware`.
 *  */ 

app.route('/auth', authController);
app.route('/auth-log', authLogController);
app.route('/user', userController);
app.get('/', (c) => c.text("hello"));
app.route('/api/categories', categoryController);

export default app;

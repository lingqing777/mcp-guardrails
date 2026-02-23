/**
 * 认证与会话管理模块
 * 提供 Dashboard 和 API 的登录保护
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==================== 配置 ====================

// 默认凭据 (兜底，users.json 中找不到用户时使用)
const DEFAULT_USERNAME = process.env.DASHBOARD_USERNAME || 'admin';
const DEFAULT_PASSWORD = process.env.DASHBOARD_PASSWORD || 'guardrails';

// Session 配置
const SESSION_EXPIRY_MS = parseInt(process.env.SESSION_EXPIRY_MS) || 24 * 60 * 60 * 1000;
const SESSION_COOKIE_NAME = 'mcp_session';

// 用户文件路径
const USERS_FILE = process.env.USERS_FILE ||
  path.resolve(__dirname, '../../../config/users.json');

// ==================== 用户存储 ====================

function loadUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) return { users: [] };
    const raw = fs.readFileSync(USERS_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return { users: [] };
  }
}

function saveUsers(data) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error('[Auth] 保存用户文件失败:', err.message);
  }
}

// ==================== Session 存储 ====================

// 内存存储 (生产环境可替换为 Redis)
const sessions = new Map();

/**
 * 生成安全的 Session ID
 */
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * 创建新会话
 */
function createSession(username, role) {
  const sessionId = generateSessionId();
  const session = {
    id: sessionId,
    username,
    role: role || 'viewer',
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_EXPIRY_MS,
  };
  sessions.set(sessionId, session);
  return session;
}

/**
 * 验证会话
 */
function validateSession(sessionId) {
  if (!sessionId) return null;

  const session = sessions.get(sessionId);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }

  return session;
}

/**
 * 销毁会话
 */
function destroySession(sessionId) {
  sessions.delete(sessionId);
}

/**
 * 清理过期会话 (定期调用)
 */
function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [sessionId, session] of sessions) {
    if (now > session.expiresAt) {
      sessions.delete(sessionId);
    }
  }
}

// 每小时清理一次过期会话
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

// ==================== 认证验证 ====================

/**
 * 验证用户名密码
 * 优先查 users.json，找不到则兜底比对硬编码 admin
 */
async function verifyCredentials(username, password) {
  // 先查 users.json
  const { users } = loadUsers();
  const user = users.find(u => u.username === username);
  if (user) {
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (ok) return { ok: true, role: user.role };
    return { ok: false };
  }

  // 兜底：硬编码 admin 账号
  if (username === DEFAULT_USERNAME && password === DEFAULT_PASSWORD) {
    return { ok: true, role: 'admin' };
  }

  return { ok: false };
}

/**
 * 从请求中提取 Session ID
 */
function getSessionIdFromRequest(req) {
  // 优先从 Cookie 获取
  const cookies = req.headers.cookie;
  if (cookies) {
    const match = cookies.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`));
    if (match) return match[1];
  }

  // 备选：从 Authorization header 获取 (Bearer token)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // 备选：从查询参数获取
  return req.query?.session;
}

// ==================== Express 中间件 ====================

/**
 * 认证中间件 - 保护需要登录的路由
 */
function authMiddleware(req, res, next) {
  const sessionId = getSessionIdFromRequest(req);
  const session = validateSession(sessionId);

  if (!session) {
    if (req.path.startsWith('/api/') || req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: '请先登录',
        code: 'AUTH_REQUIRED'
      });
    }
    return res.redirect('/login');
  }

  req.session = session;
  next();
}

/**
 * 可选认证中间件 - 不强制要求登录，但会解析会话
 */
function optionalAuthMiddleware(req, res, next) {
  const sessionId = getSessionIdFromRequest(req);
  req.session = validateSession(sessionId);
  next();
}

// ==================== 登录页面 HTML ====================

const loginPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Guardrails - 登录</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e4e4e4;
        }
        .login-container {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        .login-header { text-align: center; margin-bottom: 32px; }
        .login-header h1 {
            font-size: 28px;
            font-weight: 600;
            background: linear-gradient(90deg, #00d4ff, #7b68ee);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
        }
        .login-header p { color: #888; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #aaa; font-size: 14px; }
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 16px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }
        .form-group input::placeholder { color: #555; }
        .login-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s, transform 0.2s;
        }
        .login-btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .login-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .error-message {
            background: rgba(255, 71, 87, 0.1);
            border: 1px solid rgba(255, 71, 87, 0.3);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 20px;
            color: #ff4757;
            font-size: 14px;
            display: none;
        }
        .error-message.show { display: block; }
        .footer-hint { text-align: center; margin-top: 24px; color: #666; font-size: 12px; }
        .footer-hint a { color: #667eea; text-decoration: none; }
        .footer-hint a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>MCP Guardrails</h1>
            <p>安全仪表盘登录</p>
        </div>
        <div id="error-message" class="error-message"></div>
        <form id="login-form">
            <div class="form-group">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" placeholder="请输入用户名" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" placeholder="请输入密码" required autocomplete="current-password">
            </div>
            <button type="submit" class="login-btn" id="login-btn">登录</button>
        </form>
        <div class="footer-hint">
            默认账号: admin / guardrails &nbsp;|&nbsp; <a href="/register">注册新账号</a>
        </div>
    </div>
    <script>
        const form = document.getElementById('login-form');
        const errorEl = document.getElementById('error-message');
        const loginBtn = document.getElementById('login-btn');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            loginBtn.disabled = true;
            loginBtn.textContent = '登录中...';
            errorEl.classList.remove('show');
            try {
                const response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                if (response.ok && data.success) {
                    window.location.href = '/';
                } else {
                    errorEl.textContent = data.message || '登录失败';
                    errorEl.classList.add('show');
                }
            } catch (err) {
                errorEl.textContent = '网络错误，请稍后重试';
                errorEl.classList.add('show');
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = '登录';
            }
        });
    </script>
</body>
</html>`;

// ==================== 注册页面 HTML ====================

const registerPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Guardrails - 注册</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e4e4e4;
        }
        .login-container {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        .login-header { text-align: center; margin-bottom: 32px; }
        .login-header h1 {
            font-size: 28px;
            font-weight: 600;
            background: linear-gradient(90deg, #00d4ff, #7b68ee);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
        }
        .login-header p { color: #888; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #aaa; font-size: 14px; }
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 16px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        }
        .form-group input::placeholder { color: #555; }
        .login-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s, transform 0.2s;
        }
        .login-btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .login-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .error-message {
            background: rgba(255, 71, 87, 0.1);
            border: 1px solid rgba(255, 71, 87, 0.3);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 20px;
            color: #ff4757;
            font-size: 14px;
            display: none;
        }
        .error-message.show { display: block; }
        .success-message {
            background: rgba(0, 255, 136, 0.1);
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 20px;
            color: #00ff88;
            font-size: 14px;
            display: none;
        }
        .success-message.show { display: block; }
        .footer-hint { text-align: center; margin-top: 24px; color: #666; font-size: 12px; }
        .footer-hint a { color: #667eea; text-decoration: none; }
        .footer-hint a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>MCP Guardrails</h1>
            <p>注册新账号</p>
        </div>
        <div id="error-message" class="error-message"></div>
        <div id="success-message" class="success-message"></div>
        <form id="register-form">
            <div class="form-group">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" placeholder="3-32位字母、数字或下划线" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" placeholder="至少6位" required autocomplete="new-password">
            </div>
            <div class="form-group">
                <label for="confirm">确认密码</label>
                <input type="password" id="confirm" name="confirm" placeholder="再次输入密码" required autocomplete="new-password">
            </div>
            <button type="submit" class="login-btn" id="register-btn">注册</button>
        </form>
        <div class="footer-hint">
            已有账号？<a href="/login">返回登录</a>
        </div>
    </div>
    <script>
        const form = document.getElementById('register-form');
        const errorEl = document.getElementById('error-message');
        const successEl = document.getElementById('success-message');
        const registerBtn = document.getElementById('register-btn');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm').value;

            errorEl.classList.remove('show');
            successEl.classList.remove('show');

            if (password !== confirm) {
                errorEl.textContent = '两次输入的密码不一致';
                errorEl.classList.add('show');
                return;
            }

            registerBtn.disabled = true;
            registerBtn.textContent = '注册中...';
            try {
                const response = await fetch('/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                if (response.ok && data.success) {
                    successEl.textContent = '注册成功！即将跳转到登录页...';
                    successEl.classList.add('show');
                    form.reset();
                    setTimeout(() => window.location.href = '/login', 1500);
                } else {
                    errorEl.textContent = data.message || '注册失败';
                    errorEl.classList.add('show');
                }
            } catch (err) {
                errorEl.textContent = '网络错误，请稍后重试';
                errorEl.classList.add('show');
            } finally {
                registerBtn.disabled = false;
                registerBtn.textContent = '注册';
            }
        });
    </script>
</body>
</html>`;

// ==================== 路由注册 ====================

/**
 * 注册认证相关路由
 */
function registerAuthRoutes(app) {
  // 登录页面
  app.get('/login', (req, res) => {
    const sessionId = getSessionIdFromRequest(req);
    if (validateSession(sessionId)) return res.redirect('/');
    res.send(loginPageHTML);
  });

  // 注册页面
  app.get('/register', (req, res) => {
    const sessionId = getSessionIdFromRequest(req);
    if (validateSession(sessionId)) return res.redirect('/');
    res.send(registerPageHTML);
  });

  // 登录 API
  app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ success: false, message: '请输入用户名和密码' });
    }

    const result = await verifyCredentials(username, password);
    if (!result.ok) {
      return res.status(401).json({ success: false, message: '用户名或密码错误' });
    }

    const session = createSession(username, result.role);
    res.cookie(SESSION_COOKIE_NAME, session.id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: SESSION_EXPIRY_MS,
    });

    res.json({
      success: true,
      message: '登录成功',
      role: session.role,
      expiresAt: session.expiresAt,
    });
  });

  // 注册 API
  app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
    }
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
      return res.status(400).json({ success: false, message: '用户名只能包含字母、数字和下划线，长度3-32位' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: '密码至少6位' });
    }
    // 不允许与硬编码 admin 同名
    if (username === DEFAULT_USERNAME) {
      return res.status(400).json({ success: false, message: '该用户名已存在' });
    }

    const data = loadUsers();
    if (data.users.find(u => u.username === username)) {
      return res.status(400).json({ success: false, message: '该用户名已存在' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    data.users.push({
      username,
      passwordHash,
      role: 'viewer',
      createdAt: new Date().toISOString(),
    });
    saveUsers(data);

    res.json({ success: true, message: '注册成功' });
  });

  // 登出 API
  app.post('/auth/logout', (req, res) => {
    const sessionId = getSessionIdFromRequest(req);
    if (sessionId) destroySession(sessionId);
    res.clearCookie(SESSION_COOKIE_NAME);
    res.json({ success: true, message: '已登出' });
  });

  // 检查登录状态 API
  app.get('/auth/status', (req, res) => {
    const sessionId = getSessionIdFromRequest(req);
    const session = validateSession(sessionId);

    if (session) {
      res.json({
        authenticated: true,
        username: session.username,
        role: session.role,
        expiresAt: session.expiresAt,
      });
    } else {
      res.json({ authenticated: false });
    }
  });
}

// ==================== 导出 ====================

export {
  authMiddleware,
  optionalAuthMiddleware,
  registerAuthRoutes,
  validateSession,
  getSessionIdFromRequest,
  SESSION_COOKIE_NAME,
};

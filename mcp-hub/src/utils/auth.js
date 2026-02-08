/**
 * 认证与会话管理模块
 * 提供 Dashboard 和 API 的登录保护
 */

import crypto from 'crypto';

// ==================== 配置 ====================

// 默认凭据 (可通过环境变量覆盖)
const DEFAULT_USERNAME = process.env.DASHBOARD_USERNAME || 'admin';
const DEFAULT_PASSWORD = process.env.DASHBOARD_PASSWORD || 'guardrails';

// Session 配置
const SESSION_EXPIRY_MS = parseInt(process.env.SESSION_EXPIRY_MS) || 24 * 60 * 60 * 1000; // 24小时
const SESSION_COOKIE_NAME = 'mcp_session';

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
function createSession(username) {
  const sessionId = generateSessionId();
  const session = {
    id: sessionId,
    username,
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

  // 检查是否过期
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
 */
function verifyCredentials(username, password) {
  return username === DEFAULT_USERNAME && password === DEFAULT_PASSWORD;
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
    // 检查是否是 API 请求
    if (req.path.startsWith('/api/') || req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: '请先登录',
        code: 'AUTH_REQUIRED'
      });
    }
    // 网页请求重定向到登录页
    return res.redirect('/login');
  }

  // 将会话信息附加到请求对象
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
        .login-header {
            text-align: center;
            margin-bottom: 32px;
        }
        .login-header h1 {
            font-size: 28px;
            font-weight: 600;
            background: linear-gradient(90deg, #00d4ff, #7b68ee);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
        }
        .login-header p {
            color: #888;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #aaa;
            font-size: 14px;
        }
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
        .form-group input::placeholder {
            color: #555;
        }
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
        .login-btn:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }
        .login-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
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
        .error-message.show {
            display: block;
        }
        .footer-hint {
            text-align: center;
            margin-top: 24px;
            color: #666;
            font-size: 12px;
        }
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
            默认账号: admin / guardrails
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
                    // 登录成功，跳转到首页
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

// ==================== 路由注册 ====================

/**
 * 注册认证相关路由
 */
function registerAuthRoutes(app) {
  // 登录页面
  app.get('/login', (req, res) => {
    // 如果已登录，重定向到首页
    const sessionId = getSessionIdFromRequest(req);
    if (validateSession(sessionId)) {
      return res.redirect('/');
    }
    res.send(loginPageHTML);
  });

  // 登录 API
  app.post('/auth/login', (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: '请输入用户名和密码'
      });
    }

    if (!verifyCredentials(username, password)) {
      return res.status(401).json({
        success: false,
        message: '用户名或密码错误'
      });
    }

    // 创建会话
    const session = createSession(username);

    // 设置 Cookie
    res.cookie(SESSION_COOKIE_NAME, session.id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: SESSION_EXPIRY_MS,
    });

    res.json({
      success: true,
      message: '登录成功',
      expiresAt: session.expiresAt
    });
  });

  // 登出 API
  app.post('/auth/logout', (req, res) => {
    const sessionId = getSessionIdFromRequest(req);
    if (sessionId) {
      destroySession(sessionId);
    }
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
        expiresAt: session.expiresAt
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
  SESSION_COOKIE_NAME
};

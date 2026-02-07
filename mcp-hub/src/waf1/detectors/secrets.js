/**
 * Secrets 检测器
 * 移植自 Invariant runtime/utils/secrets.py
 * 原始来源: Yelp detect-secrets 项目
 */

const SECRETS_PATTERNS = {
  // GitHub Tokens
  github_personal_token:  /ghp_[A-Za-z0-9_]{36}/,
  github_oauth_token:     /gho_[A-Za-z0-9_]{36}/,
  github_user_token:      /ghu_[A-Za-z0-9_]{36}/,
  github_server_token:    /ghs_[A-Za-z0-9_]{36}/,
  github_refresh_token:   /ghr_[A-Za-z0-9_]{36}/,
  github_fine_grained:    /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/,

  // AWS
  aws_access_key:         /(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}/,
  aws_secret_key:         /(?:aws).{0,20}(?:secret|key|pwd|pass|token).{0,20}['"][0-9a-zA-Z\/+=]{40}['"]/i,
  aws_session_token:      /(?:aws).{0,20}(?:session).{0,20}['"][0-9a-zA-Z\/+=]{100,}['"]/i,

  // OpenAI
  openai_api_key:         /sk-[a-zA-Z0-9]{48}/,
  openai_project_key:     /sk-proj-[a-zA-Z0-9\-_]{80,}/,

  // GitLab
  gitlab_token:           /glpat-[a-zA-Z0-9\-_]{20,}/,
  gitlab_runner_token:    /GR1348941[a-zA-Z0-9\-_]{20,}/,

  // Slack
  slack_token:            /xox[abpors]-(?:\d+-)+[a-z0-9]+/i,
  slack_webhook:          /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/,

  // Azure
  azure_storage_key:      /AccountKey=[a-zA-Z0-9+\/=]{88}/,
  azure_connection_string:/DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+\/=]{88}/,
  azure_sas_token:        /[?&]sig=[a-zA-Z0-9%]+&se=\d+/,

  // Google
  google_api_key:         /AIza[0-9A-Za-z\-_]{35}/,
  google_oauth_id:        /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/,
  google_oauth_secret:    /GOCSPX-[a-zA-Z0-9\-_]{28}/,

  // Stripe
  stripe_secret_key:      /sk_live_[0-9a-zA-Z]{24,}/,
  stripe_publishable_key: /pk_live_[0-9a-zA-Z]{24,}/,
  stripe_restricted_key:  /rk_live_[0-9a-zA-Z]{24,}/,

  // Twilio
  twilio_api_key:         /SK[0-9a-fA-F]{32}/,

  // Discord
  discord_token:          /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/,
  discord_webhook:        /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/,

  // Telegram
  telegram_bot_token:     /\d{9,10}:[A-Za-z0-9_-]{35}/,

  // SendGrid
  sendgrid_api_key:       /SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/,

  // Mailchimp
  mailchimp_api_key:      /[a-f0-9]{32}-us\d{1,2}/,

  // npm / PyPI
  npm_token:              /npm_[a-zA-Z0-9]{36}/,
  pypi_token:             /pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9\-_]{50,}/,

  // 私钥
  private_key:            /-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----/,
  pgp_private_key:        /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/,

  // JWT
  jwt_token:              /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/,

  // 通用
  bearer_token:           /Bearer\s+[a-zA-Z0-9\-_.~+\/]{20,}/,
  basic_auth:             /Basic\s+[A-Za-z0-9+\/=]{20,}/,
  generic_api_key:        /api[_-]?key\s*[:=]\s*['"]?[a-zA-Z0-9]{32,}['"]?/i,
  generic_secret:         /secret\s*[:=]\s*['"]?[a-zA-Z0-9]{20,}['"]?/i,
  generic_password:       /password\s*[:=]\s*['"]?[^\s'"]{8,}['"]?/i,
  generic_token:          /token\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{20,}['"]?/i,
};

/**
 * 检测文本中的敏感凭证
 * @param {string} text - 待检测文本
 * @param {object} cache - 缓存对象
 * @returns {Array} 匹配结果
 */
export function detectSecrets(text, cache) {
  const cacheKey = `secrets:${text.substring(0, 200)}`;
  if (cache) {
    const cached = cache.get(cacheKey);
    if (cached) return cached;
  }

  const matches = [];
  for (const [type, pattern] of Object.entries(SECRETS_PATTERNS)) {
    const regex = new RegExp(pattern.source, pattern.flags + (pattern.flags.includes('g') ? '' : 'g'));
    let match;
    while ((match = regex.exec(text)) !== null) {
      matches.push({
        type,
        value: match[0].substring(0, 8) + '***',  // 脱敏
        start: match.index,
        end: match.index + match[0].length,
      });
    }
  }

  if (cache) cache.set(cacheKey, matches);
  return matches;
}

export { SECRETS_PATTERNS };

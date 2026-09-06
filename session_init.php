<?php
/**
 * Session Initialization
 * Uses Redis-backed sessions via RedisSessionHandler for best performance and scalability.
 * Falls back to database-backed sessions (DbSessionHandler), then file-based sessions.
 */
if (session_status() === PHP_SESSION_NONE) {
    $useRedis = ($_ENV['REDIS_SESSIONS_ENABLED'] ?? 'true') === 'true';
    $handler = null;

    // ==================== Layer 1: Redis Sessions (best) ====================
    if ($useRedis) {
        try {
            $redisClientPath = __DIR__ . '/pos/admin/config/RedisClient.php';
            $redisSessionPath = __DIR__ . '/pos/admin/config/RedisSessionHandler.php';

            if (file_exists($redisClientPath) && file_exists($redisSessionPath)) {
                require_once $redisClientPath;
                require_once $redisSessionPath;

                $redis = new RedisClient(
                    $_ENV['REDIS_HOST'] ?? '127.0.0.1',
                    (int)($_ENV['REDIS_PORT'] ?? 6379),
                    (float)($_ENV['REDIS_TIMEOUT'] ?? 1.0)
                );

                if ($redis->ping()) {
                    $handler = new RedisSessionHandler($redis);
                    session_set_save_handler($handler, true);
                    error_log('Session handler: Redis');
                }
            }
        } catch (\Throwable $e) {
            error_log('RedisSessionHandler init failed: ' . $e->getMessage());
        }
    }

    // ==================== Layer 2: DB Sessions (fallback) ====================
    if (!isset($handler)) {
        try {
            $useDbSessions = ($_ENV['DB_SESSIONS_ENABLED'] ?? 'true') === 'true';
            if ($useDbSessions) {
                $dbSessionConfigPath = __DIR__ . '/pos/admin/config/DbSessionHandler.php';
                $configPath = __DIR__ . '/pos/admin/config/config.php';

                if (file_exists($dbSessionConfigPath) && file_exists($configPath)) {
                    require_once $dbSessionConfigPath;

                    global $mysqli;
                    if (!isset($mysqli) || !$mysqli) {
                        require_once $configPath;
                    }

                    if (isset($mysqli) && $mysqli) {
                        $handler = new DbSessionHandler($mysqli);
                        session_set_save_handler($handler, true);
                        error_log('Session handler: Database');
                    }
                }
            }
        } catch (\Throwable $e) {
            error_log('DbSessionHandler init failed: ' . $e->getMessage());
        }
    }

    // ==================== Layer 3: File Sessions (last resort) ====================
    if (!isset($handler)) {
        $sessDir = __DIR__ . '/sessions';
        if (is_dir($sessDir) && is_writable($sessDir)) {
            ini_set('session.save_path', $sessDir);
        }
        error_log('Session handler: File');
    }

    // ==================== Common Session Settings ====================
    $secure = ($_ENV['SESSION_COOKIE_SECURE'] ?? 'false') === 'true';
    $httponly = ($_ENV['SESSION_COOKIE_HTTPONLY'] ?? 'true') === 'true';
    $samesite = $_ENV['SESSION_COOKIE_SAMESITE'] ?? 'Lax';
    $lifetime = (int)($_ENV['SESSION_LIFETIME'] ?? 7200);

    session_set_cookie_params([
        'lifetime' => $lifetime,
        'path' => '/',
        'domain' => '',
        'secure' => $secure,
        'httponly' => $httponly,
        'samesite' => $samesite
    ]);

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');

    session_start();
}


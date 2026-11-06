<?php
declare(strict_types=1);

/**
 * 로컬 사용자·세션 색인·처리한 웹훅을 SQLite 에 둔다. 실제 시스템은 쓰던 DB 에 같은 컬럼을 둔다.
 *
 * - users.iam_subject_id: IAM sub. 계정 연결의 키
 * - app_sessions: PHP 세션 ID ↔ (sub, sid) 색인. back-channel 로그아웃·퇴사 웹훅이 끝낼 세션을 여기서 찾는다
 *   (PHP 세션 파일만으로는 "이 사용자의 세션"을 찾을 수 없다)
 */
final class Store
{
    private PDO $db;

    public function __construct(string $path)
    {
        $this->db = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $this->db->exec('PRAGMA busy_timeout = 3000');
        $this->db->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS users (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                iam_subject_id TEXT UNIQUE,
                emp_no         TEXT,
                name           TEXT,
                active         INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS app_sessions (
                session_id TEXT PRIMARY KEY,
                sub        TEXT NOT NULL,
                sid        TEXT
            );
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                delivery_id TEXT PRIMARY KEY,
                received_at INTEGER NOT NULL
            );
            SQL);
        // 미리 있던 로컬 계정 (iam_subject_id 가 비어 있어 첫 로그인 때 사번으로 연결된다)
        $this->db->exec("INSERT OR IGNORE INTO users (id, emp_no, name) VALUES (1, 'D-001', '기존 사용자')");
    }

    /** sub 로 찾고, 없으면 사번으로 찾아 연결하고, 그래도 없으면 만든다 (JIT). 이메일로는 연결하지 않는다 */
    public function linkAccount(string $sub, ?string $empNo, ?string $name): array
    {
        $user = $this->one('SELECT * FROM users WHERE iam_subject_id = ?', [$sub]);
        if ($user === null && $empNo !== null && $empNo !== '') {
            $user = $this->one('SELECT * FROM users WHERE iam_subject_id IS NULL AND emp_no = ?', [$empNo]);
            if ($user !== null) {
                $this->db->prepare('UPDATE users SET iam_subject_id = ? WHERE id = ?')->execute([$sub, $user['id']]);
            }
        }
        if ($user === null) {
            $this->db->prepare('INSERT INTO users (iam_subject_id, emp_no, name) VALUES (?, ?, ?)')->execute([$sub, $empNo, $name]);
            $user = $this->one('SELECT * FROM users WHERE id = ?', [(int) $this->db->lastInsertId()]);
        }
        return $user;
    }

    public function userById(int $id): ?array
    {
        return $this->one('SELECT * FROM users WHERE id = ?', [$id]);
    }

    /** 퇴사: 로컬 계정을 끈다 (실제 시스템은 권한도 모두 회수한다) */
    public function disableBySubject(string $sub): void
    {
        $this->db->prepare('UPDATE users SET active = 0 WHERE iam_subject_id = ?')->execute([$sub]);
    }

    public function indexSession(string $sessionId, string $sub, ?string $sid): void
    {
        $this->db->prepare('INSERT OR REPLACE INTO app_sessions (session_id, sub, sid) VALUES (?, ?, ?)')->execute([$sessionId, $sub, $sid]);
    }

    public function forgetSession(string $sessionId): void
    {
        $this->db->prepare('DELETE FROM app_sessions WHERE session_id = ?')->execute([$sessionId]);
    }

    /** @return string[] sid 가 있으면 그 로그인 세션만, 없으면 그 사용자(sub)의 모든 세션 */
    public function sessionIds(?string $sub, ?string $sid = null): array
    {
        $stmt = $sid !== null
            ? $this->db->prepare('SELECT session_id FROM app_sessions WHERE sid = ?')
            : $this->db->prepare('SELECT session_id FROM app_sessions WHERE sub = ?');
        $stmt->execute([$sid ?? $sub]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    /** 처음 받은 전달이면 true. 같은 X-Didrakon-Delivery 가 다시 오면 false */
    public function firstDelivery(string $deliveryId): bool
    {
        $stmt = $this->db->prepare('INSERT OR IGNORE INTO webhook_deliveries (delivery_id, received_at) VALUES (?, ?)');
        $stmt->execute([$deliveryId, time()]);
        return $stmt->rowCount() === 1;
    }

    private function one(string $sql, array $args): ?array
    {
        $stmt = $this->db->prepare($sql);
        $stmt->execute($args);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }
}

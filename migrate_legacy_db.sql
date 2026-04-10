-- Миграция существующей БД (старый schema без заданий 5–6) к актуальной схеме.
-- Выполните на сервере: mysql -u USER -p form_app < migrate_legacy_db.sql
-- MariaDB 10.3+ / MySQL 8+

SET NAMES utf8mb4;

USE form_app;

-- Колонки учётной записи пользователя анкеты
ALTER TABLE form_submissions
  ADD COLUMN IF NOT EXISTS user_login VARCHAR(64) NULL AFTER biography,
  ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255) NULL AFTER user_login;

-- Заполнить старые строки (уникальный логин + хеш-заглушка; войти по ним нельзя — только новые заявки получают реальный пароль)
UPDATE form_submissions
SET
  user_login = CONCAT('legacy_', id),
  password_hash = SHA2(CONCAT('legacy_', id, '_migrated'), 256)
WHERE user_login IS NULL OR user_login = '';

ALTER TABLE form_submissions
  MODIFY user_login VARCHAR(64) NOT NULL,
  MODIFY password_hash VARCHAR(255) NOT NULL;

-- Уникальность логина (пропускаем, если индекс уже есть — например после полного schema.sql)
SET @have_uq := (
  SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'form_submissions'
    AND INDEX_NAME = 'uq_form_submissions_user_login'
);
SET @sql_uq := IF(@have_uq = 0,
  'ALTER TABLE form_submissions ADD UNIQUE KEY uq_form_submissions_user_login (user_login)',
  'SELECT ''index_ok'' AS _');
PREPARE iq FROM @sql_uq;
EXECUTE iq;
DEALLOCATE PREPARE iq;

-- Таблицы заданий 5–6 (если ещё не созданы)
CREATE TABLE IF NOT EXISTS user_sessions (
  session_id CHAR(64) NOT NULL,
  submission_id INT UNSIGNED NOT NULL,
  csrf_token CHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  PRIMARY KEY (session_id),
  KEY idx_user_sessions_submission (submission_id),
  KEY idx_user_sessions_expires_at (expires_at),
  CONSTRAINT fk_user_sessions_submission
    FOREIGN KEY (submission_id) REFERENCES form_submissions (id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admins (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  login VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_admins_login (login)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO admins (login, password_hash) VALUES
  ('admin', SHA2('admin123', 256))
ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash);

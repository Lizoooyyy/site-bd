-- MariaDB / MySQL: форма заявок, 3НФ
SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

CREATE DATABASE IF NOT EXISTS form_app
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE form_app;

-- Справочник языков программирования
CREATE TABLE IF NOT EXISTS programming_languages (
  id TINYINT UNSIGNED NOT NULL AUTO_INCREMENT,
  code VARCHAR(32) NOT NULL,
  display_name VARCHAR(64) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_programming_languages_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Заявка (одна строка на отправку формы)
CREATE TABLE IF NOT EXISTS form_submissions (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  full_name VARCHAR(150) NOT NULL,
  phone VARCHAR(64) NOT NULL,
  email VARCHAR(255) NOT NULL,
  birth_date DATE NOT NULL,
  gender ENUM('male', 'female', 'other') NOT NULL,
  biography TEXT NOT NULL,
  user_login VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  contract_accepted TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_form_submissions_user_login (user_login)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 1:N: одна заявка — несколько выбранных языков (каждая строка — один язык)
CREATE TABLE IF NOT EXISTS submission_programming_languages (
  submission_id INT UNSIGNED NOT NULL,
  language_id TINYINT UNSIGNED NOT NULL,
  PRIMARY KEY (submission_id, language_id),
  CONSTRAINT fk_spl_submission
    FOREIGN KEY (submission_id) REFERENCES form_submissions (id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_spl_language
    FOREIGN KEY (language_id) REFERENCES programming_languages (id)
    ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Серверные сессии пользователей формы.
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

-- Администраторы (логин + хеш пароля для HTTP Basic Auth).
CREATE TABLE IF NOT EXISTS admins (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  login VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_admins_login (login)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Заполнение справочника (коды совпадают с value в форме)
INSERT INTO programming_languages (code, display_name) VALUES
  ('pascal', 'Pascal'),
  ('c', 'C'),
  ('cpp', 'C++'),
  ('javascript', 'JavaScript'),
  ('php', 'PHP'),
  ('python', 'Python'),
  ('java', 'Java'),
  ('haskell', 'Haskel'),
  ('clojure', 'Clojure'),
  ('prolog', 'Prolog'),
  ('scala', 'Scala'),
  ('go', 'Go')
ON DUPLICATE KEY UPDATE display_name = VALUES(display_name);

-- Тестовая учётка администратора:
-- login: admin
-- password: admin123
INSERT INTO admins (login, password_hash) VALUES
  ('admin', SHA2('admin123', 256))
ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash);

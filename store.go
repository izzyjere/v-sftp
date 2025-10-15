package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strings"
	"go.uber.org/zap"
)

type Permission uint8

const (
	PermRead   Permission = 1 << 0 //1
	PermList   Permission = 1 << 1 //2
	PermWrite  Permission = 1 << 2 //4
	PermDelete Permission = 1 << 3 //8
)

type User struct {
	ID           int
	DisplayName  string
	GroupName    string
	Username     string
	PasswordHash sql.NullString // bcrypt hash
	PublicKey    sql.NullString
	RootPath     string
	Perms        Permission
	Disabled     bool
}

type UserStore struct {
	db     *sql.DB
	logger *zap.SugaredLogger
}

func NewUserStore(dsn string) *UserStore {
	dbType := getEnvOrDefault("DB_TYPE", "sqlite")
	db, err := sql.Open(dbType, dsn)
	if err != nil {
		panic(err)
	}
	logger, err := initLogger()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Ensure DB schema exists; if sftp_users table missing, apply ddl.sql
	if err := applyDDLIfNeeded(dbType,db, logger); err != nil {
		logger.Fatalf("Failed to apply DDL: %v", err)
	}

	return &UserStore{db: db, logger: logger}
}

func applyDDLIfNeeded(dbType string, db *sql.DB, logger *zap.SugaredLogger) error {
	logger.Infof("Checking for sftp_users table")
	// Try a simple query against the table
	var tmp int
	err := db.QueryRow("SELECT 1 FROM sftp_users LIMIT 1").Scan(&tmp)
	if err == nil {
		logger.Infof("sftp_users table exists")
		return nil
	}
	logger.Warnf("sftp_users table not found or inaccessible (%v). Attempting to apply ddl.sql", err)

	ddlBytes, rerr := os.ReadFile(dbType + "_ddl.sql")
	if rerr != nil {
		logger.Errorf("Failed to read ddl.sql: %v", rerr)
		return rerr
	}
	ddl := string(ddlBytes)

	// Execute the DDL. Some drivers/drivers' Exec may not accept multiple statements;
	// try Exec as-is first, then fallback to splitting on semicolon.
	if _, execErr := db.Exec(ddl); execErr == nil {
		logger.Infof("Applied ddl.sql successfully")
		return nil
	} else {
		logger.Warnf("Exec of ddl.sql failed: %v — attempting split-exec", execErr)
		// naive split; acceptable for simple SQL files
		statements := splitSQLStatements(ddl)
		tx, terr := db.Begin()
		if terr != nil {
			logger.Errorf("Failed to begin transaction for applying DDL: %v", terr)
			return terr
		}
		for _, stmt := range statements {
			if stmt = trimWhitespace(stmt); stmt == "" {
				continue
			}
			if _, serr := tx.Exec(stmt); serr != nil {
				_ = tx.Rollback()
				logger.Errorf("Failed to execute statement: %v", serr)
				return serr
			}
		}
		if cerr := tx.Commit(); cerr != nil {
			logger.Errorf("Failed to commit DDL transaction: %v", cerr)
			return cerr
		}
		logger.Infof("Applied ddl.sql successfully (split-exec)")
		return nil
	}
}

func splitSQLStatements(ddl string) []string {
	return []string(filterEmpty(strings.Split(ddl, ";")))
}

func trimWhitespace(s string) string { return strings.TrimSpace(s) }

func filterEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func (s *UserStore) FetchUserByUsername(ctx context.Context, username string) (*User, error) {
	s.logger.Infof("Fetching user by username: %s", username)
	query := `SELECT id, display_name, group_name, username, password_hash, public_key, root_path, perms, disabled FROM sftp_users WHERE username = ?`
	row := s.db.QueryRowContext(ctx, query, username)
	var user User
	err := row.Scan(&user.ID, &user.DisplayName, &user.GroupName, &user.Username, &user.PasswordHash, &user.PublicKey, &user.RootPath, &user.Perms, &user.Disabled)
	if err != nil {
		s.logger.Errorf("Error fetching user: %v", err)
		return nil, err
	}
	return &user, nil
}

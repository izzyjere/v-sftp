package main

import (
	"context"
	"database/sql"
	"log"

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
	return &UserStore{db: db, logger: logger}
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

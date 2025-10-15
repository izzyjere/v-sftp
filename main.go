package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"gopkg.in/natefinch/lumberjack.v2"
)

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func initLogger() (*zap.SugaredLogger, error) {
	logPath := getEnvOrDefault("LOG_PATH", "./logs/sftp.log")
	logLevel := getEnvOrDefault("LOG_LEVEL", "info")
	//Create log directory if not exists
	if err := os.MkdirAll(strings.TrimSuffix(logPath, "/"+filepath.Base(logPath)), 0755); err != nil {
		return nil, err
	}
	rotator := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    20, // megabytes
		MaxBackups: 7,
		MaxAge:     14, // days
		Compress:   true,
	}
	file := zapcore.AddSync(rotator)
	console := zapcore.AddSync(os.Stdout)

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05.000")
	encoderCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder

	var debugLevel zapcore.Level
	if strings.ToLower(logLevel) == "debug" {
		debugLevel = zapcore.DebugLevel
	} else {
		debugLevel = zapcore.InfoLevel
	}
	fileCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderCfg),
		file,
		debugLevel,
	)
	consoleCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderCfg),
		console,
		zapcore.DebugLevel,
	)
	core := zapcore.NewTee(fileCore, consoleCore)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1)).Sugar()
	return logger, nil
}

func main() {
	logger, err := initLogger()
	if err != nil {
		panic(err)
	}
	var (
		dsn         = getEnvOrDefault("DB_DSN", "./data/sftp.db")
		listenAddr  = getEnvOrDefault("LISTEN_ADDR", "0.0.0.0:2022")
		hostKeyPath = getEnvOrDefault("HOST_KEY_PATH", "./data/host_key")
	)
	logger.Infof("Starting SFTP server on %s", listenAddr)
	store := NewUserStore(dsn)
	if store == nil {
		logger.Fatal("Failed to connect to the user store.")
	}
	defer store.db.Close()

	hostSigner, err := loadOrCreateHostKey(hostKeyPath)
	if err != nil {
		logger.Fatalf("Failed to load or create host key: %v", err)
	}
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: false,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			logger.Infof("Password auth attempt for user: %s", c.User())
			cxt, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			user, err := store.FetchUserByUsername(cxt, c.User())
			if err != nil {
				logger.Warnf("User %s not found: %v", c.User(), err)
				return nil, err
			}
			if user.Disabled {
				logger.Warnf("User %s is disabled", c.User())
				return nil, fmt.Errorf("user disabled")
			}
			if !user.PasswordHash.Valid {
				logger.Warnf("User %s has no password set", c.User())
				return nil, fmt.Errorf("no password set")
			}
			//use bcrypt to compare password
			if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash.String), pass); err != nil {
				logger.Warnf("Invalid password for user %s: %v", c.User(), err)
				return nil, fmt.Errorf("invalid password")
			}
			//attach user info to session
			perms := &ssh.Permissions{Extensions: map[string]string{"username": user.Username}}
			return perms, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			logger.Infof("Public key auth attempt for user: %s", c.User())
			cxt, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			user, err := store.FetchUserByUsername(cxt, c.User())
			if err != nil {
				logger.Warnf("User %s not found: %v", c.User(), err)
				return nil, err
			}
			if user.Disabled {
				logger.Warnf("User %s is disabled", c.User())
				return nil, fmt.Errorf("user disabled")
			}
			if !user.PublicKey.Valid {
				logger.Warnf("User %s has no public key set", c.User())
				return nil, fmt.Errorf("no public key set")
			}
			authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.PublicKey.String))
			if err != nil {
				logger.Warnf("Invalid public key for user %s: %v", c.User(), err)
				return nil, fmt.Errorf("invalid public key")
			}
			// compare marshaled keys to avoid depending on ssh.KeysEqual
			if !bytes.Equal(key.Marshal(), authorizedKey.Marshal()) {
				logger.Warnf("Public key mismatch for user %s", c.User())
				return nil, fmt.Errorf("public key mismatch")
			}
			//attach user info to session
			perms := &ssh.Permissions{Extensions: map[string]string{"username": user.Username}}
			return perms, nil
		},
	}

	sshConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	logger.Infof("Listening on %s", listenAddr)
	for {
		nConn, err := listener.Accept()
		if err != nil {
			logger.Errorf("Failed to accept incoming connection: %v", err)
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
			if err != nil {
				logger.Errorf("Failed to handshake: %v", err)
				return
			}
			logger.Infof("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
			// Discard global requests
			go ssh.DiscardRequests(reqs)
			//handle channels
			for newChannel := range chans {
				if newChannel.ChannelType() != "session" {
					newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
					logger.Warnf("Unknown channel type: %s", newChannel.ChannelType())
					continue
				}
				channel, requests, err := newChannel.Accept()
				if err != nil {
					logger.Errorf("Could not accept channel: %v", err)
					continue
				}
				go func(in <-chan *ssh.Request) {
					for req := range in {
						if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
							// Handle SFTP subsystem request
							//Accept the request
							req.Reply(true, nil)
							// Fetch user info from session
							username := sshConn.Permissions.Extensions["username"]
							cxt, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							user, err := store.FetchUserByUsername(cxt, username)
							cancel()
							if err != nil {
								logger.Errorf("Failed to fetch user %s: %v", username, err)
								channel.Close()
								return
							}
							handler := &SftpHandler{user: user, logger: logger}
							handlers := sftp.Handlers{FileGet: handler, FilePut: handler, FileCmd: handler, FileList: handler}
							server := sftp.NewRequestServer(channel, handlers)
							if err := server.Serve(); err == io.EOF {
								server.Close()
								logger.Infof("SFTP client exited session.")
							} else if err != nil {
								logger.Errorf("SFTP server completed with error: %v", err)
							}
							return
						} else {
							req.Reply(false, nil)
							logger.Warnf("Unknown request type: %s", req.Type)
							continue
						}
					}
				}(requests)
			}
		}(nConn)
	}
}

// Load or create host key
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if _, err := os.Stat(path); err == nil {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ssh.ParsePrivateKey(b)
	}
	// generate new RSA key (not great for production; replace with persistent key)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privDER := x509.MarshalPKCS1PrivateKey(key)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := pem.Encode(f, privBlock); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(privDER)
}

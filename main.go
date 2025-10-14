package main

import (
	"database/sql"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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


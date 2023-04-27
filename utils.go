package main

import (
	"fmt"
	"github.com/logzio/logzio-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"strings"
	"time"
)

const (
	LogLevelDebug     = "debug"
	LogLevelInfo      = "info"
	LogLevelWarn      = "warn"
	LogLevelError     = "error"
	LogLevelFatal     = "fatal"
	LogLevelPanic     = "panic"
	defaultLogLevel   = LogLevelInfo
	envLogLevel       = "LOG_LEVEL"
	envLogzioToken    = "LOGZIO_TOKEN"
	envLogzioListener = "LOGZIO_LISTENER"
	envIncludePathsRegexes   = "INCLUDE_PATHS_REGEXES"
	envExcludePathsRegexes   = "EXCLUDE_PATHS_REGEXES"
	maxBulkSizeBytes  = 10 * 1024 * 1024 // 10 MB
)

func getHookLogLevel() string {
	validLogLevels := []string{LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError, LogLevelFatal, LogLevelPanic}
	logLevel := os.Getenv(envLogLevel)
	for _, validLogLevel := range validLogLevels {
		if validLogLevel == logLevel {
			return validLogLevel
		}
	}

	return defaultLogLevel
}

func getToken() (string, error) {
	token := os.Getenv(envLogzioToken)
	if len(token) == 0 {
		return "", fmt.Errorf("%s should be set", envLogzioToken)
	}

	return token, nil
}

func getListener() (string, error) {
	listener := os.Getenv(envLogzioListener)
	if len(listener) == 0 {
		return "", fmt.Errorf("%s must be set", envLogzioListener)
	}

	return listener, nil
}

func getNewLogzioSender() (*logzio.LogzioSender, error) {
	token, err := getToken()
	if err != nil {
		return nil, err
	}
	listener, err := getListener()
	if err != nil {
		return nil, err
	}

	logLevel := getHookLogLevel()
	var logzioLogger *logzio.LogzioSender
	if logLevel == LogLevelDebug {
		logzioLogger, err = logzio.New(
			token,
			logzio.SetUrl(listener),
			logzio.SetInMemoryQueue(true),
			logzio.SetDebug(os.Stdout),
			logzio.SetinMemoryCapacity(maxBulkSizeBytes), //bytes
			logzio.SetDrainDuration(time.Second*5),
			logzio.SetDebug(os.Stdout),
			logzio.SetCompress(true),
		)
	} else {
		logzioLogger, err = logzio.New(
			token,
			logzio.SetUrl(listener),
			logzio.SetInMemoryQueue(true),
			logzio.SetDebug(os.Stdout),
			logzio.SetinMemoryCapacity(maxBulkSizeBytes), //bytes
			logzio.SetDrainDuration(time.Second*5),
			logzio.SetCompress(true),
		)
	}

	if err != nil {
		return nil, err
	}

	return logzioLogger, nil
}

func getLogger() *zap.Logger {
	logLevel := getLogLevel()
	cfg := zap.Config{
		Encoding:         "json",
		Level:            zap.NewAtomicLevelAt(logLevel),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:   "message",
			LevelKey:     "level",
			EncodeLevel:  zapcore.CapitalLevelEncoder,
			TimeKey:      "time",
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			CallerKey:    "caller",
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}
	logger, _ := cfg.Build()
	return logger
}

func getLogLevel() zapcore.Level {
	logLevelStr := getHookLogLevel()
	levelsMap := map[string]zapcore.Level{
		LogLevelDebug: zapcore.DebugLevel,
		LogLevelInfo:  zapcore.InfoLevel,
		LogLevelWarn:  zapcore.WarnLevel,
		LogLevelError: zapcore.ErrorLevel,
		LogLevelPanic: zapcore.PanicLevel,
		LogLevelFatal: zapcore.FatalLevel,
	}

	return levelsMap[logLevelStr]
}

func getIncludePathsRegex() []string {
	pathsStr := os.Getenv(envIncludePathsRegexes)
	if len(pathsStr) == 0 {
		return nil
	}

	return strings.Split(strings.Replace(pathsStr, " ", "", -1), ",")
}

func getExcludePathsRegex() []string {
	pathsStr := os.Getenv(envExcludePathsRegexes)
	if len(pathsStr) == 0 {
		return nil
	}

	return strings.Split(strings.Replace(pathsStr, " ", "", -1), ",")
}
package main

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
)

const (
	LogLevelDebug      = "debug"
	LogLevelInfo       = "info"
	LogLevelWarn       = "warn"
	LogLevelError      = "error"
	LogLevelFatal      = "fatal"
	LogLevelPanic      = "panic"
	defaultLogLevel    = LogLevelInfo
	defaultPolicyName  = "LambdaAccessBuckets"
	defaultRoleName    = "LogzioS3Hook"
	envLogLevel        = "LOG_LEVEL"
	envMainFunctionArn = "MAIN_FUNC_ARN"
	envAccountId       = "ACCOUNT_ID"
	envPolicyName      = "POLICY_NAME"
	envRoleName        = "ROLE_NAME"
)

func getCTLogLevel() string {
	validLogLevels := []string{LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError, LogLevelFatal, LogLevelPanic}
	logLevel := os.Getenv(envLogLevel)
	for _, validLogLevel := range validLogLevels {
		if validLogLevel == logLevel {
			return validLogLevel
		}
	}

	return defaultLogLevel
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
	logLevelStr := getCTLogLevel()
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

func getMainFunctionArn() string {
	return os.Getenv(envMainFunctionArn)
}

func getAccountId() string {
	return os.Getenv(envAccountId)
}

func getPolicyName() string {
	pn := os.Getenv(envPolicyName)
	if len(pn) == 0 {
		pn = defaultPolicyName
	}

	return pn
}

func getRoleName() string {
	rn := os.Getenv(envRoleName)
	if len(rn) == 0 {
		rn = defaultRoleName
	}

	return rn
}

func getPolicyDocumentBuckets() string {
	return `{
	"Version": "2012-10-17",
	"Statement": [{
		"Action": [
			"s3:GetObject"
		],
		"Resource": [
			"arn:aws:s3:::*"
		],
		"Effect": "Allow"
	}]
}`
}

package main

import (
	"fmt"
	"github.com/logzio/logzio-go"
	"os"
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
		)
	} else {
		logzioLogger, err = logzio.New(
			token,
			logzio.SetUrl(listener),
			logzio.SetInMemoryQueue(true),
			logzio.SetDebug(os.Stdout),
			logzio.SetinMemoryCapacity(maxBulkSizeBytes), //bytes
			logzio.SetDrainDuration(time.Second*5),
		)
	}

	if err != nil {
		return nil, err
	}

	return logzioLogger, nil
}

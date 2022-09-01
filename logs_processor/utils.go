package logs_processor

import (
	"os"
)

const (
	envLogType      = "LOG_TYPE"
	envPathToFields = "PATH_TO_FIELDS"
)

func getLogType() string {
	logType := os.Getenv(envLogType)
	if len(logType) == 0 {
		logType = defaultLogType
	}

	return logType
}

func getControlTowerParsing() string {
	return os.Getenv(envPathToFields)
}

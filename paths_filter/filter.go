package paths_filter

import (
	"fmt"
	"go.uber.org/zap"
	"regexp"
)

func IsIncludePath(path string, pathsRegex []string, logger *zap.Logger) bool {
	for _, pathRegex := range pathsRegex {
		matched, err := regexp.MatchString(fmt.Sprintf(`%s`, pathRegex), path)
		if err != nil {
			logger.Error(fmt.Sprintf("Error occurred while trying to paths_filter path: %s", err.Error()))
		}

		if matched {
			return true
		}
	}

	return false
}

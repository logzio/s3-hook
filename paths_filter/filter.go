package paths_filter

import (
	"fmt"
	"go.uber.org/zap"
	"regexp"
)

func IsFilterPath(path string, pathsRegexes []string, logger *zap.Logger) bool {
	for _, pathRegex := range pathsRegexes {
		matched, err := regexp.MatchString(fmt.Sprintf(`%s`, pathRegex), path)
		if err != nil {
			logger.Error(fmt.Sprintf("Error occurred while trying to match path to regexes list: %s", err.Error()))
		}

		if matched {
			return true
		}
	}

	return false
}

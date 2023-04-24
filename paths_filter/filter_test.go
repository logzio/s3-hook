package paths_filter

import (
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"testing"
)

var (
	logger         *zap.Logger
	pathsToInclude []string
)

func TestIsIncludePathInclude(t *testing.T) {
	logger, pathsToInclude = setUpTest()
	validPaths := []string{
		"some12/path-abc/ok/file.gz",
		"bucket/some04/path-xyz/ok/foo/logs.log",
		"another/to/filter/on",
	}
	for _, path := range validPaths {
		include := IsFilterPath(path, pathsToInclude, logger)
		assert.True(t, include)
	}
}

func setUpTest() (*zap.Logger, []string) {
	cfg := zap.Config{
		Encoding:         "json",
		Level:            zap.NewAtomicLevelAt(zapcore.DebugLevel),
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
	logger, _ = cfg.Build()
	validPaths := []string{`some\d{2}/path-\w{3,6}/ok`, `another/to/filter/on`}
	return logger, validPaths
}

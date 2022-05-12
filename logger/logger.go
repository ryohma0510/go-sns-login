package logger

import (
	"github.com/rs/zerolog"
	"os"
)

type Logger struct {
	Logger *zerolog.Logger
}

func New(isDebug bool) *Logger {
	var logLevel zerolog.Level
	if isDebug {
		logLevel = zerolog.DebugLevel
	} else {
		logLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(logLevel)
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()

	return &Logger{Logger: &logger}
}

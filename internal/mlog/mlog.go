package mlog

import (
	"oauth2-api/internal/logger"

	"github.com/gin-gonic/gin"
)

const (
	AppLog     = "logApp"
	CustomLog  = "customLog"
	SummaryLog = "logSummary"
)

func Log(ctx *gin.Context) logger.CustomLoggerService {
	switch v := ctx.Value(CustomLog).(type) {
	case logger.CustomLoggerService:
		return v
	default:
		return logger.NewCustomLogger(logger.NewDefaultLoggerService(), logger.NewDefaultLoggerService(), logger.NewTimer(), logger.NewMaskingService())
	}
}

func LogApp(ctx *gin.Context) logger.ILogger {
	switch v := ctx.Value(AppLog).(type) {
	case logger.ILogger:
		return v
	default:
		return logger.NewDefaultLoggerService()
	}
}

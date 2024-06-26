package utils

import (
	"context"

	"go.uber.org/zap"
)

type Logger interface {
	Error(ctx context.Context, message string, fields ...zap.Field)
	Info(ctx context.Context, message string, fields ...zap.Field)
}

type logger struct {
	logger *zap.Logger
}

func NewLogger(l *zap.Logger) Logger {
	return &logger{l}
}

func (l *logger) Error(ctx context.Context, message string, fields ...zap.Field) {
	if reqID, ok := ctx.Value("requestID").(string); ok {
		fields = append(fields, zap.String("requestID", reqID))
	}

	if userID, ok := ctx.Value("userID").(string); ok {
		fields = append(fields, zap.String("requestID", userID))
	}
	l.logger.Error(message, fields...)
}

func (l *logger) Info(ctx context.Context, message string, fields ...zap.Field) {
	l.logger.Info(message, fields...)
}

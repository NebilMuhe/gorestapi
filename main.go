package main

import (
	"context"
	"os"
	"time"

	_ "github.com/lib/pq"
	"gitlab.com/Nebil/data"
	"gitlab.com/Nebil/handler"
	"gitlab.com/Nebil/helpers"
	"gitlab.com/Nebil/service"
	"go.uber.org/zap"
)

func main() {
	logger := helpers.NewLogger()
	err := helpers.LoadEnv()
	if err != nil {
		logger.Error(context.Background(), "unable to load enviromental variable", zap.Error(err))
		return
	}
	logger.Info(context.Background(), "loaded the enviromental variable successfully")

	if err != nil {
		return
	}

	DB_DRIVER := os.Getenv("DB_DRIVER")
	DB_URI := os.Getenv("DB_URI")
	PORT := os.Getenv("PORT")

	db, err := data.ConnectDB(DB_DRIVER, DB_URI)
	if err != nil {
		logger.Error(context.Background(), "unable to connect to database", zap.Error(err))
		return
	}
	defer db.Close()
	logger.Info(context.Background(), "connected successfully to the database")

	repo := data.NewUserRepository(db, logger)
	service := service.NewUserService(repo, logger)
	handlers := handler.NewUserHandler(service, logger)
	router := handler.NewServer()

	router.Router.Use(handler.TimeoutMiddleware(time.Second * 5))
	router.Router.POST("/api/register", handlers.RegisterUserHandler)
	router.Router.POST("/api/login", handlers.LoginUserHandler)
	router.Router.POST("/api/refresh", handlers.RefreshTokenHandler)

	if err := router.Router.Run(":" + PORT); err != nil {
		logger.Error(context.Background(), "unable to run", zap.Error(err))
	}
	// logger.Info(context.Background(), "Listening on port", zap.String("PORT", PORT))
}

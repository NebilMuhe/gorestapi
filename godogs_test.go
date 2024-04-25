package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.com/Nebil/data"
	"gitlab.com/Nebil/handler"
	"gitlab.com/Nebil/helpers"
	"gitlab.com/Nebil/service"
	"go.uber.org/zap"
)

type UserRegistration struct {
	response     string
	errorMessage string
	status       int
}

type User struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

type CustomError struct {
	Error        string `json:"error"`
	ErrorMessage string `json:"errormessage"`
	Status       int    `json:"status"`
}

func setupRouter() (*gin.Engine, *sql.DB, error) {
	logger := helpers.NewLogger()
	err := helpers.LoadEnv()
	if err != nil {
		logger.Error(context.Background(), "unable to load enviromental variable", zap.Error(err))
		return nil, nil, err
	}
	logger.Info(context.Background(), "loaded the enviromental variable successfully")

	DB_DRIVER := os.Getenv("DB_DRIVER")
	DB_URI := os.Getenv("DB_URI")

	db, err := data.ConnectDB(DB_DRIVER, DB_URI)
	if err != nil {
		logger.Error(context.Background(), "unable to connect to database", zap.Error(err))
		return nil, nil, err
	}

	logger.Info(context.Background(), "connected successfully to the database")

	repo := data.NewUserRepository(db, logger)
	service := service.NewUserService(repo, logger)
	handlers := handler.NewUserHandler(service, logger)
	router := handler.NewServer()

	router.Router.Use(handler.TimeoutMiddleware(time.Second * 5))
	router.Router.POST("/api/register", handlers.RegisterUserHandler)
	router.Router.POST("/api/login", handlers.LoginUserHandler)
	router.Router.POST("/api/refresh", handlers.RefreshTokenHandler)

	router.Router.POST("/", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"response": "welocme"})
	})

	return router.Router, db, nil
}

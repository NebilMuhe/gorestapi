package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
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

	DB_URI := os.Getenv("DB_URI")
	PORT := os.Getenv("PORT")

	db, err := data.ConnectDB(DB_URI)
	if err != nil {
		logger.Error(context.Background(), "unable to connect to database", zap.Error(err))
		return
	}
	defer db.Close(context.Background())
	logger.Info(context.Background(), "connected successfully to the database")

	repo := data.NewUserRepository(db, logger)
	service := service.NewUserService(repo, logger)
	handlers := handler.NewUserHandler(service, logger)
	router := handler.NewServer()

	router.Router.Use(handler.TimeoutMiddleware(time.Second * 5))
	router.Router.POST("/api/register", handlers.RegisterUserHandler)
	router.Router.POST("/api/login", handlers.LoginUserHandler)
	router.Router.POST("/api/refresh", handlers.RefreshTokenHandler)

	router.Router.GET("/home", func(ctx *gin.Context) {
		fmt.Println("this returns welcome message")
		ctx.JSON(http.StatusOK, gin.H{"response": "welcome to the home page"})
	})

	if err := router.Router.Run(":" + PORT); err != nil {
		logger.Error(context.Background(), "unable to run", zap.Error(err))
	}
	// logger.Info(context.Background(), "Listening on port", zap.String("PORT", PORT))
}

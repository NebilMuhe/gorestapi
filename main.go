package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	// "github.com/golang-migrate/migrate"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/cockroachdb"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	_ "github.com/lib/pq"
	"gitlab.com/Nebil/data"
	"gitlab.com/Nebil/handler"
	"gitlab.com/Nebil/helpers"
	"gitlab.com/Nebil/service"
	"gitlab.com/Nebil/utils"
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
	MIGRATION_URL := os.Getenv("MIGRATION_URL")
	PORT := os.Getenv("PORT")
	DB_SOURCE := os.Getenv("DB_SOURCE")

	runDBMigration(MIGRATION_URL, DB_SOURCE, logger)

	db, err := data.ConnectDB(DB_URI)
	if err != nil {
		logger.Error(context.Background(), "unable to connect to database", zap.Error(err))
		return
	}
	defer db.Close(context.Background())
	logger.Info(context.Background(), "connected successfully to the database")

	repo := data.NewUserRepository(db, logger)
	logger.Info(context.Background(), "repo started")
	service := service.NewUserService(repo, logger)
	logger.Info(context.Background(), "service started")
	handlers := handler.NewUserHandler(service, logger)
	logger.Info(context.Background(), "handler started")

	router := handler.NewServer()

	router.Router.Use(handler.TimeoutMiddleware(time.Second * 5))
	router.Router.GET("/home", func(ctx *gin.Context) {
		fmt.Println("this returns welcome message")
		ctx.JSON(http.StatusOK, gin.H{"response": "welcome to the home page"})
	})

	logger.Info(context.Background(), "home endpoint works started")
	// router.Router.POST("/api/register", func(ctx *gin.Context) {
	// 	logger.Info(context.Background(), "inside register handler works")
	// })
	// router.Router.Use(handler.TimeoutMiddleware(time.Second * 5))
	// logger.Info(context.Background(), "timeout handler works")
	router.Router.POST("/api/register", handlers.RegisterUserHandler)
	// router.Router.POST("/api/register", func(ctx *gin.Context) {
	// 	logger.Info(context.Background(), "inside register handler works")
	// })
	// logger.Info(context.Background(), "register handler works")
	router.Router.POST("/api/login", handlers.LoginUserHandler)
	router.Router.POST("/api/refresh", handlers.RefreshTokenHandler)

	if err := router.Router.Run(":" + PORT); err != nil {
		logger.Error(context.Background(), "unable to run", zap.Error(err))
	}
	// logger.Info(context.Background(), "Listening on port", zap.String("PORT", PORT))
}

func runDBMigration(migrationURL string, dbSource string, logger utils.Logger) {
	migration, err := migrate.New(migrationURL, dbSource)
	if err != nil {
		logger.Error(context.Background(), "can not create migrate instance", zap.Error(err))
	}

	if err := migration.Up(); err != nil && err != migrate.ErrNoChange {
		logger.Error(context.Background(), "failed to run migrate up", zap.Error(err))
	}

	logger.Info(context.Background(), "db migrate successfully")
}

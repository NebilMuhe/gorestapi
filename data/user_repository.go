package data

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
	db "gitlab.com/Nebil/db/sqlc"
	"gitlab.com/Nebil/service"
	"go.uber.org/zap"
)

type userRepository struct {
	Database *sql.DB
	queries  *db.Queries
	logger   zap.Logger
}

func NewUserRepository(database *sql.DB, logger zap.Logger) service.UserRepository {
	return &userRepository{
		Database: database,
		queries:  db.New(database),
		logger:   logger,
	}
}

func ConnectDB(driver, url string) (*sql.DB, error) {
	db, err := sql.Open(driver, url)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Register implements service.UserRepository.
func (u *userRepository) Register(*gin.Context, *service.User) (*service.User, error) {
	return &service.User{}, nil
}

// Exists implements service.UserRepository.
func (u *userRepository) Exists(ctx *gin.Context, user *service.User) (bool, error) {
	_, err := u.queries.FindBYEmail(ctx, user.Email)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	_, err = u.queries.FindBYUsername(ctx, user.Username)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	return true, nil
}

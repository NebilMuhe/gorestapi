package data

import (
	"database/sql"

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
func (u *userRepository) Register(ctx *gin.Context, user *service.User) (*service.User, error) {
	c := ctx.Request.Context()
	errChan := make(chan error)
	resChan := make(chan *service.User)

	go func() {
		arg := db.RegisterUserParams{
			Username: user.Username,
			Email:    user.Email,
			Password: user.Password,
		}
		usr, err := u.queries.RegisterUser(ctx, arg)

		if err != nil {
			errChan <- err
			return
		}
		resChan <- &service.User{
			Username: usr.Username,
			Email:    usr.Email,
		}
	}()

	select {
	case <-c.Done():
		err := c.Err()
		return &service.User{}, err
	case err := <-errChan:
		return &service.User{}, err
	case res := <-resChan:
		return res, nil
	}

}

// Exists implements service.UserRepository.
func (u *userRepository) Exists(ctx *gin.Context, user *service.User) (bool, error) {
	usr, _ := u.queries.FindBYUsername(ctx, user.Username)
	us, _ := u.queries.FindBYEmail(ctx, user.Email)

	if usr.Username == "" && us.Email == "" {
		return false, nil
	}
	return true, nil
}

package controller

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jeffthorne/tasky/auth"
	"github.com/jeffthorne/tasky/database"
	"github.com/jeffthorne/tasky/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var SECRET_KEY string = os.Getenv("SECRET_KEY")
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

func SignUp(c *gin.Context) {

	var user models.User
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Println("Received signup request payload")

	// ✅ ADD: Early null check for required fields (moved up before any logic)
	if user.Name == nil || user.Email == nil || user.Password == nil {
		log.Println("Signup failed: missing fields", "name:", user.Name, "email:", user.Email, "password:", user.Password)
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, email, and password are required"})
		return
	}

	// ✅ ADD: Logging input to confirm what was received
	log.Println("Attempting signup for:", *user.Email)

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	// emailCount, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
	defer cancel()

	// if err != nil {
	// 	log.Panic(err)
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
	// }

	password := HashPassword(*user.Password)
	user.Password = &password

	// if emailCount > 0 {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "User with this email already exists!"})
	// 	return
	// }
	user.ID = primitive.NewObjectID()

	// ✅ ADD: Log before insert
	log.Println("Inserting user record for:", *user.Email)

	resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
	if insertErr != nil {
		log.Println("Mongo insert error:", insertErr) // ✅ Log the real error message
		msg := fmt.Sprintf("user item was not created")
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}
	defer cancel()
	userId := user.ID.Hex()
	username := *user.Name

	// ✅ ADD: Log success
	log.Println("User inserted with ID:", userId)

	token, err, expirationTime := auth.GenerateJWT(userId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while generating token"})
		return
	}

	// if user.Name == nil || user.Email == nil || user.Password == nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "name, email, and password are required"})
	// 	return
	// }

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: expirationTime,
	})

	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "userID",
		Value:   userId,
		Expires: expirationTime,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:    "username",
		Value:   username,
		Expires: expirationTime,
	})

	c.JSON(http.StatusOK, resultInsertionNumber)

}
func Login(c *gin.Context) {
	var user models.User
	var foundUser models.User

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bind error"})
		return
	}

	if user.Email == nil || user.Password == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
		return
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
	defer cancel()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": " email or password is incorrect"})
		return
	}

	passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
	defer cancel()

	if passwordIsValid != true {
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	if foundUser.Email == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found!"})
		return
	}
	userId := foundUser.ID.Hex()
	username := ""
	if foundUser.Name != nil {
		username = *foundUser.Name
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User record missing name"})
		return
	}

	shouldRefresh, err, expirationTime := auth.RefreshToken(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh token error"})
		return
	}

	if shouldRefresh {
		token, err, expirationTime := auth.GenerateJWT(userId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while generating token"})
			return
		}

		http.SetCookie(c.Writer, &http.Cookie{
			Name:    "token",
			Value:   token,
			Expires: expirationTime,
		})

		http.SetCookie(c.Writer, &http.Cookie{
			Name:    "userID",
			Value:   userId,
			Expires: expirationTime,
		})
		http.SetCookie(c.Writer, &http.Cookie{
			Name:    "username",
			Value:   username,
			Expires: expirationTime,
		})

	} else {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:    "userID",
			Value:   userId,
			Expires: expirationTime,
		})
		http.SetCookie(c.Writer, &http.Cookie{
			Name:    "username",
			Value:   username,
			Expires: expirationTime,
		})
	}
	c.JSON(http.StatusOK, gin.H{"msg": "login successful"})
}

func Todo(c *gin.Context) {
	session := auth.ValidateSession(c)
	if session {
		c.HTML(http.StatusOK, "todo.html", nil)
	}
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("email or password is incorrect")
		check = false
	}

	return check, msg
}

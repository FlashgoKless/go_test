package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var userStore = map[string]*User{}
var db *gorm.DB

type User struct {
    ID         uint   `gorm:"primaryKey"`
    Email      string 
    Password   string
    TOTP       string // secret
    Enabled2FA bool
}

func main() {
	dsn := "host=localhost user=postgres password=IQ777&exe777iq dbname=totp_demo port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	//Auto-migrate schema
	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatal("Migration failed:", err)
	}

	r := gin.Default()

	//Routes
	r.GET("/", homePage)
	r.POST("/signup", signup)
	r.GET("/qrcode/:email", serveQRCode)
	r.POST("/enable-2fa", enable2FA)
	r.POST("/login", login)

	log.Println("Server running at https://localhost:8443")

	server := &http.Server{
		Addr:    ":8443",
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Fatal(server.ListenAndServeTLS("TLS_test.crt", "TLS_test_key_private.pem"))

}

func homePage(c *gin.Context) {
	c.String(200, "Welcome! Use /signup, /enable-2fa, /login")
}

// POST /signup {email, password}
func signup(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MyWebApp",
		AccountName: req.Email,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate secret"})
		return
	}

	user := User{Email: req.Email, Password: req.Password, TOTP: key.Secret(), Enabled2FA: false}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(400, gin.H{"error": "email already exists"})
		return
	}

	c.JSON(200, gin.H{
		"message":   "signup successful",
		"email":     req.Email,
		"secret":    key.Secret(),
		"qrcode":    fmt.Sprintf("https://localhost:8080/qrcode/%s", req.Email),
		"verify2FA": "POST /enable-2fa {email, code}",
	})
}

// GET /qrcode/:email
func serveQRCode(c *gin.Context) {
	email := c.Param("email")

	var user User
	if err := db.First(&user, "email = ?", email).Error; err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	otpauthURL := fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		"MyWebApp", email, user.TOTP, "MyWebApp",
	)

	png, _ := qrcode.Encode(otpauthURL, qrcode.Medium, 256)
	c.Data(200, "image/png", png)
}

// POST /enable-2fa
func enable2FA(c *gin.Context) {
    var req struct {
        Email string `json:"email"`
        Code  string `json:"code"`
    }
    if err := c.BindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "bad request"})
        return
    }

    var user User
    if err := db.First(&user, "email = ?", req.Email).Error; err != nil {
        c.JSON(404, gin.H{"error": "user not found"})
        return
    }

    valid, err := totp.ValidateCustom(req.Code, user.TOTP, time.Now(), totp.ValidateOpts{
        Period:    30,
        Skew:      1,
        Digits:    otp.DigitsSix,
        Algorithm: otp.AlgorithmSHA1,
    })
    if err != nil {
        c.JSON(500, gin.H{"error": "error validating code"})
        return
    }
    if !valid {
        c.JSON(401, gin.H{"error": "invalid code"})
        return
    }

    user.Enabled2FA = true
    if err := db.Save(&user).Error; err != nil {
        c.JSON(500, gin.H{"error": "failed to update user"})
        return
    }

    c.JSON(200, gin.H{"message": "2FA enabled"})
}

func login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad request"})
		return
	}

	var user User
	if err := db.First(&user, "email = ?", req.Email).Error; err != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	if user.Password != req.Password {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	if user.Enabled2FA {
		if !totp.Validate(req.Code, user.TOTP) {
			c.JSON(401, gin.H{"error": "invalid 2FA code"})
			return
		}
	}

	c.JSON(200, gin.H{"message": "login successful"})
}
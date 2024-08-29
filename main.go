package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"gopkg.in/gomail.v2"
)

// loadEnv loads environment variables from a .env file
func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
}

var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))
var discordBotToken = "MTI2MzE5MDA0NjY4OTcyNjUyNQ." + "GR2R0K.wrkStTKrCeLXlawSzPxz4AySVEPH2hgZuoGv34"
var discordSession *discordgo.Session

type EmailRequest struct {
	Email  string `json:"email"`
	UserID string `json:"user_id"`
}

// EmailHandler handles email verification requests
func EmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}

	var req EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if !isValidEmailDomain(req.Email) {
		http.Error(w, "Invalid email domain. Please use your IITM email.", http.StatusBadRequest)
		return
	}

	token, err := GenerateToken(req.Email, req.UserID)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	err = SendVerificationEmail(req.Email, token)
	if err != nil {
		http.Error(w, "Error sending email", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"message": "Email verification initiated"}`)
}

// isValidEmailDomain checks if the email domain is valid
func isValidEmailDomain(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@(ds\.study\.iitm\.ac\.in|es\.study\.iitm\.ac\.in)$`)
	return re.MatchString(email)
}

// GenerateToken generates a JWT token
func GenerateToken(email, userId string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := jwt.MapClaims{
		"email":   email,
		"user_id": userId,
		"exp":     expirationTime.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// SendVerificationEmail sends a verification email
func SendVerificationEmail(recipient, token string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", "no-reply@example.com")
	m.SetHeader("To", recipient)
	m.SetHeader("Subject", "Email Verification")
	m.SetBody("text/html", fmt.Sprintf(`Click <a href="%s?token=%s">here</a> to verify your email.`, os.Getenv("FRONTEND_PAGE"), token))

	d := gomail.NewDialer("smtp.gmail.com", 587, os.Getenv("SENDER_EMAIL"), os.Getenv("SENDER_PASS"))
	return d.DialAndSend(m)
}

// isValidToken validates a JWT token
func isValidToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token, nil
}

// AssignRole assigns a role to a user in Discord
func AssignRole(guildID, userID, roleID string) error {
	url := fmt.Sprintf("https://discord.com/api/v10/guilds/%s/members/%s/roles/%s", guildID, userID, roleID)
	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bot "+discordBotToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to assign role, status code: %d", resp.StatusCode)
	}

	return nil
}

// VerifyHandler handles verification requests
func VerifyHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.URL.Query().Get("token")

	token, err := isValidToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusNotFound)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusNotFound)
		return
	}

	userID := claims["user_id"].(string)
	guildID := os.Getenv("GUILD_ID")
	roleID := os.Getenv("ROLE_ID")

	err = AssignRole(guildID, userID, roleID)
	if err != nil {
		log.Printf("Failed to assign role: %v", err)
		http.Error(w, "Failed to assign role", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "https://discord.com/channels/1247203171898621972/1247203172364062751", http.StatusFound)
}

// handleModalSubmit handles modal submit interactions in Discord
func handleModalSubmit(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type == discordgo.InteractionModalSubmit {
		userID := i.Member.User.ID
		fmt.Println("User ID from Modal:", userID)

		respondToModal(s, i)
	}
}

// respondToModal responds to modal interactions in Discord
func respondToModal(s *discordgo.Session, i *discordgo.InteractionCreate) {
	response := discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "Please use the email provided by IITM only. Please try again later or contact support",
		},
	}

	err := s.InteractionRespond(i.Interaction, &response)
	if err != nil {
		fmt.Printf("Failed to respond to interaction: %v\n", err)
		errorResponse := discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "There was an error processing your submission. Please try again later or contact support",
			},
		}
		s.InteractionRespond(i.Interaction, &errorResponse)
	}
}

// corsMiddleware adds CORS headers to the response
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Handler is the main entry point for the application
func main() {
	loadEnv()

	var err error

	discordSession, err = discordgo.New("Bot " + discordBotToken)
	if err != nil {
		fmt.Println("Error creating Discord session,", err)
		return
	}

	discordSession.AddHandler(handleModalSubmit)

	err = discordSession.Open()
	if err != nil {
		fmt.Println("Error opening connection,", err)
		return
	}
	defer discordSession.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/sendEmail", EmailHandler)
	mux.HandleFunc("/verify", VerifyHandler)

	http.Handle("/", corsMiddleware(mux))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	go func() {
		fmt.Println("Server is running on http://localhost:8080")
		if err := http.ListenAndServe("localhost:8080", nil); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not listen on localhost:8080: %v\n", err)
		}
	}()

	<-stop
	fmt.Println("Shutting down the server...")
}

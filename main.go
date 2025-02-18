package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/GitIBB/chirpy/internal/auth"
	"github.com/GitIBB/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	Platform       string
	jwtSecret      string
}

type ChirpRequest struct {
	Body string `json:"body"`
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type User struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"-"`
	IsChirpyRed    bool      `json:"is_chirpy_red"`
}

type userResponse struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

type updateUserInfoRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshResponse struct {
	Token string `json:"token"`
}

type Chirp struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    string    `json:"user_id"`
}

type UpgradeRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID string `json:"user_id"`
	} `json:"data"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	// Return a new http.HandlerFunc
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Increment the fileserverHits counter
		cfg.fileserverHits.Add(1)

		// Call the next handler with the current ResponseWriter and Request
		next.ServeHTTP(w, r)
	})
}

// Handlers

func (cfg *apiConfig) numHitsHandler(w http.ResponseWriter, r *http.Request) {
	currentHits := cfg.fileserverHits.Load()
	formattedHitsString := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, currentHits)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(formattedHitsString))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.Platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Not allowed")
		return
	}
	err := cfg.DB.DeleteAllUsers(r.Context())
	if err != nil {
		respondWithError(w, 400, "Error deleting users")
		return
	}
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Reset succesful"))
}

func (cfg *apiConfig) createNewUserHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := &createUserRequest{}
	err := decoder.Decode(params)
	if err != nil {
		respondWithError(w, 400, "Error Decoding Parameters")
		return
	}

	// password validation
	if params.Password == "" {
		respondWithError(w, 400, "Password is required")
		return
	}

	if len(params.Password) < 5 {
		respondWithError(w, 400, "Password must be at least 6 characters")
		return
	}

	// password is valid, call to HashPassword
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, 500, "Error hashing password")
		return
	}

	user, err := cfg.DB.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		fmt.Println("Database error:", err)
		respondWithError(w, 400, "Error Creating User")
		return
	}

	response := User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}

	respondWithJSON(w, http.StatusCreated, response)
}

func (cfg *apiConfig) userLoginHandler(w http.ResponseWriter, r *http.Request) {
	const hoursInSeconds = 3600
	decoder := json.NewDecoder(r.Body)
	params := &loginUserRequest{}
	err := decoder.Decode(params)
	if err != nil {
		respondWithError(w, 400, "Error Decoding Parameters")
		return
	}

	if params.Email == "" || params.Password == "" {
		respondWithError(w, 400, "Email and password are required")
		return
	}

	// get user by Email
	userFetch, err := cfg.DB.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	err = auth.CheckPasswordHash(params.Password, userFetch.HashedPassword)
	if err != nil {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	tokenString, err := auth.MakeJWT(
		userFetch.ID,
		cfg.jwtSecret,
		time.Duration(hoursInSeconds)*time.Second,
	)
	if err != nil {
		respondWithError(w, 500, "Error creating JWT token")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, 500, "Error generating refresh token")
		return
	}
	refreshExpiresAt := time.Now().Add(60 * 24 * time.Hour) // 60 days

	refreshParams := database.AddRefreshTokenParams{
		UserID:    userFetch.ID,
		ExpiresAt: refreshExpiresAt,
		Token:     refreshToken,
	}

	err = cfg.DB.AddRefreshToken(r.Context(), refreshParams)
	if err != nil {
		respondWithError(w, 500, "Error adding refresh token")
		return
	}

	response := userResponse{
		ID:           userFetch.ID.String(),
		CreatedAt:    userFetch.CreatedAt,
		UpdatedAt:    userFetch.UpdatedAt,
		Email:        userFetch.Email,
		IsChirpyRed:  userFetch.IsChirpyRed,
		Token:        tokenString,
		RefreshToken: refreshToken,
	}

	respondWithJSON(w, 200, response)

}

func (cfg *apiConfig) updateUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "unauthorized")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := updateUserInfoRequest{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, "Invalid request body")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, 500, "Error hashing password")
		return
	}

	newParams := database.UpdateUserInfoParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
		ID:             userID,
	}

	updateUser, err := cfg.DB.UpdateUserInfo(r.Context(), newParams)
	if err != nil {
		respondWithError(w, 500, "Error updating user")
		return
	}

	convertedUser := User{ // have to do this step because of duplicate user struct in generated SQLC code
		ID:        updateUser.ID,
		Email:     updateUser.Email,
		CreatedAt: updateUser.CreatedAt,
		UpdatedAt: updateUser.UpdatedAt,
	}

	respondWithJSON(w, 200, convertedUser)

}

func (cfg *apiConfig) upgradeToRedWebhookHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := &UpgradeRequest{}
	err := decoder.Decode(params)
	if err != nil {
		respondWithError(w, 400, "Error Decoding Parameters")
		return
	}

	if params.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	userID, err := uuid.Parse(params.Data.UserID)
	if err != nil {
		respondWithError(w, 400, "Invalid user ID")
		return
	}

	err = cfg.DB.UpgradeUserToRed(r.Context(), userID)
	if err != nil {
		respondWithError(w, 404, "User not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) addRefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	authHeader, err := auth.GetBearerToken(r.Header)
	validateToken, err := cfg.DB.ValidateRefreshToken(r.Context(), authHeader)
	if err != nil {
		respondWithError(w, 401, "Token is invalid")
		return
	}
	newAccessToken, err := auth.MakeJWT(validateToken.ID, cfg.jwtSecret, time.Hour)
	if err != nil {
		respondWithError(w, 500, "Couldn't create access token")
		return
	}

	token := refreshResponse{
		Token: newAccessToken,
	}

	respondWithJSON(w, 200, token)
}

func (cfg *apiConfig) revokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenToRevoke, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Invalid token")
		return
	}

	// revoke token in database
	err = cfg.DB.RevokeRefreshToken(r.Context(), tokenToRevoke)
	if err != nil {
		respondWithError(w, 500, "Could not revoke token")
		return
	}

	w.WriteHeader(http.StatusNoContent)

}

func (cfg *apiConfig) newChirpsHandler(w http.ResponseWriter, r *http.Request) {
	// Get and validate JWT token first
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	// Get user ID from token
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := ChirpRequest{}

	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 400, "Invalid Request")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	badWords := []string{"kerfuffle", "sharbert", "fornax"}

	cleanedBody := cleanText(params.Body, badWords)

	now := time.Now()

	dbParams := database.CreateChirpsParams{
		ID:        uuid.New(),
		CreatedAt: now,
		UpdatedAt: now,
		Body:      cleanedBody,
		UserID:    userID,
	}

	dbChirp, err := cfg.DB.CreateChirps(r.Context(), dbParams)
	if err != nil {
		respondWithError(w, 500, "Couldn't create chirp")
		return
	}

	chirp := Chirp{
		ID:        dbChirp.ID.String(),
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID.String(),
	}

	respondWithJSON(w, 201, chirp)
}

func (cfg *apiConfig) getAllChirpsHandler(w http.ResponseWriter, r *http.Request) {

	databaseChirps, err := cfg.DB.GetAllChirps(r.Context())
	if err != nil {
		respondWithError(w, 500, "Error retrieving chirps")
		return
	}
	chirps := make([]Chirp, len(databaseChirps))
	for i, dbChirp := range databaseChirps {
		chirps[i] = Chirp{
			ID:        dbChirp.ID.String(),
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID.String(),
		}
	}

	respondWithJSON(w, 200, chirps)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirpPath := r.PathValue("chirpID")
	if chirpPath == "" {
		respondWithError(w, 400, "Chirp not found")
		return
	}

	chirpUUID, err := uuid.Parse(chirpPath)
	if err != nil {
		respondWithError(w, 400, "Error in parsing chirpID to UUID")
		return
	}

	databaseChirp, err := cfg.DB.GetChirp(r.Context(), chirpUUID)
	if err != nil {
		respondWithError(w, 404, "Chirp not found")
		return
	}

	convertedChirp := Chirp{ // have to do this because of duplicate user struct in SQLC-generated code
		ID:        databaseChirp.ID.String(),
		CreatedAt: databaseChirp.CreatedAt,
		UpdatedAt: databaseChirp.UpdatedAt,
		Body:      databaseChirp.Body,
		UserID:    databaseChirp.UserID.String(),
	}

	respondWithJSON(w, 200, convertedChirp)
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	chirpIDString := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDString)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	chirp, err := cfg.DB.GetChirp(r.Context(), chirpID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if chirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "Chirp belongs to another user")
		return
	}

	err = cfg.DB.DeleteChirp(r.Context(), database.DeleteChirpParams{
		UserID: userID,
		ID:     chirpID,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to delete chirp")
		return
	}

	w.WriteHeader(http.StatusNoContent)

}

// Helper functions for endpoints

func respondWithError(w http.ResponseWriter, code int, msg string) {

	// Use: respondWithError(w, 400, "Chirp is too long")

	response := map[string]string{
		"error": msg,
	}
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonBytes)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {

	// Use: respondWithJSON(w, 200, response)

	jsonBytes, err := json.Marshal(payload)
	fmt.Println(string(jsonBytes))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonBytes)
}

func cleanText(inputText string, badWords []string) string {

	words := strings.Split(inputText, " ") // Split into individual words :: inputText starts here

	cleanedWords := []string{}
	for _, word := range words {
		isBadWord := false
		for _, badWord := range badWords {
			if strings.ToLower(word) == badWord { // convert word to lowercase and test agaisnt badWord
				isBadWord = true
				break
			}
		}
		if isBadWord {
			cleanedWords = append(cleanedWords, "****") // Replace bad words with "****"
		} else {
			cleanedWords = append(cleanedWords, word) // Keep clean words untouched
		}
	}

	// Join the cleaned words back together and return the new string
	return strings.Join(cleanedWords, " ")
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}

	dbQueries := database.New(db)

	mux := http.NewServeMux()

	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		DB:             dbQueries,
		Platform:       os.Getenv("PLATFORM"),
		jwtSecret:      os.Getenv("JWT_SECRET"),
	}

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("GET /admin/metrics", apiCfg.numHitsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.newChirpsHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createNewUserHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpsHandler)
	mux.HandleFunc("POST /api/login", apiCfg.userLoginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.addRefreshTokenHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeTokenHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUserInfoHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.upgradeToRedWebhookHandler)

	// serves homepage, needs middleware
	mux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))

	// Create Server struct with Port and Handler
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// ListenAndServe to start server
	log.Println("Starting server on :8080...")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

}

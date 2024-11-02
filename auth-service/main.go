package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

var db *sql.DB

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		mustGetEnv("DB_HOST"),
		mustGetEnv("DB_PORT"),
		mustGetEnv("DB_USER"),
		mustGetEnv("DB_PASSWORD"),
		mustGetEnv("DB_NAME"),
	)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		slog.Error("Error opening database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		slog.Error("Error pinging database", "error", err)
		os.Exit(1)
	}
	slog.Info("Connected to the database")

	http.HandleFunc("/auth", handleAuth)
	http.HandleFunc("/acl", handleACL)

	slog.Info("Starting server on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	var auth struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&auth); err != nil {
		slog.Warn("Error decoding auth request", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM mqtt_users WHERE username=$1 AND password_hash=$2)",
		auth.Username, auth.Password).Scan(&exists)

	if err != nil || !exists {
		slog.Warn("Authentication failed", "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleACL(w http.ResponseWriter, r *http.Request) {
	var acl struct {
		Username string `json:"username"`
		Topic    string `json:"topic"`
		Acc      int    `json:"acc"`
	}

	if err := json.NewDecoder(r.Body).Decode(&acl); err != nil {
		slog.Warn("Error decoding ACL request", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var allowed bool
	err := db.QueryRow(`
        SELECT EXISTS(
            SELECT 1 FROM mqtt_acls 
            WHERE username=$1 
            AND $2 LIKE topic 
            AND (
                CASE 
                    WHEN $3 = 1 THEN access IN ('read', 'readwrite')
                    WHEN $3 = 2 THEN access IN ('write', 'readwrite')
                END
            )
        )`,
		acl.Username, acl.Topic, acl.Acc).Scan(&allowed)

	if err != nil || !allowed {
		slog.Warn("ACL check failed", "error", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		slog.Error("Environment variable not set", "key", key)
		os.Exit(1)
	}
	return value
}

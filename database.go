package main

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Creds struct {
	username string
	password string
}

type RegisterCreds struct {
	username  string
	password  string
	password2 string
}

// Database struct to store the connection pool
type Database struct {
	*sql.DB
}

// Function to initialize the database connection
func InitDB() (*Database, error) {
	db, err := sql.Open("sqlite3", "./mydatabase.db")
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT,
		password TEXT
	);`)
	if err != nil {
		return nil, err
	}

	if err := (&Database{db}).CreateCardInfoTable(); err != nil {
		return nil, err
	}

	return &Database{db}, nil
}

// Function to insert a user into the database
func (db *Database) InsertUser(username, password string) error {
	tx, err := db.Begin()
	if err != nil {

		return err
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	hshdPassword := string(hashedPassword)
	_, err = tx.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hshdPassword)
	if err != nil {
		fmt.Println(err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil

}

func (db *Database) InsertCardInfo(username string, cardInfo string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	hashedCardInfo, err := bcrypt.GenerateFromPassword([]byte(cardInfo), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO card_info (username, card_info) VALUES (?, ?)", username, string(hashedCardInfo))
	if err != nil {
		fmt.Println(err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (db *Database) Auth(c Creds) (bool, error) {

	var hashedPass string

	row := db.QueryRow("SELECT password FROM users WHERE username = ?", c.username)

	err := row.Scan(&hashedPass)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(c.password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, err
	} else if err != nil {
		return false, err
	}

	return true, nil
}

func (db *Database) CreateCardInfoTable() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS card_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        card_info INT
    );`)
	if err != nil {
		return err
	}

	return nil
}

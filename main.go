package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	_ "github.com/mattn/go-sqlite3"
)

var tokenAuth *jwtauth.JWTAuth

type ViewData struct {
	IsLoggedIn  bool
	BasketItems []string
	X           int
	Account     bool
}

type User struct {
	ID       int
	Username string
	Password string
}

type CardInfo struct {
	username string
	card     string
}

type Template struct {
	htmlTemplate *template.Template
}

func init() {
	secretKey := "secret"

	tokenAuth = jwtauth.New("HS256", []byte(secretKey), nil)
}

// function that parses the html files
func Parse(path string) (Template, error) {
	htmlTemplate, err := template.ParseFiles(path)
	if err != nil {
		return Template{}, fmt.Errorf("parsing failes %v", err)
	}
	return Template{
		htmlTemplate: htmlTemplate,
	}, nil
}

// function that handles error of "execute" and passes data interface
func (t Template) Run(w http.ResponseWriter, data interface{}) {
	err := t.htmlTemplate.Execute(w, data)
	if err != nil {
		log.Printf("%v", err)
		http.Error(w, "failed to execute the template", http.StatusInternalServerError)
		return

	}
}

func (db *Database) MainHandler(tpl Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		isAuthenticated, ok := r.Context().Value("isAuthenticated").(bool)
		fmt.Println(isAuthenticated)
		if !ok {
			isAuthenticated = false
		}
		cartItems, err := r.Cookie("cart")
		if err != nil && err != http.ErrNoCookie {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Parse the cart items
		var items []string
		if cartItems != nil {
			items = strings.Split(cartItems.Value, ",")
		}

		x := len(items)
		x = x - 1
		data := ViewData{
			IsLoggedIn:  isAuthenticated,
			BasketItems: items,
			X:           x,
		}
		tpl.Run(w, data)
	}
}

func Redirection(w http.ResponseWriter, r *http.Request) {

	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func (db *Database) Checkout(w http.ResponseWriter, r *http.Request) {
	_, _, err := jwtauth.FromContext(r.Context())
	if err != nil {
		http.Error(w, "Authentication error", http.StatusUnauthorized)
		return
	}

	var Card CardInfo

	Card.card = r.FormValue("cardNumber")
	Card.username = r.FormValue("name")

	err = db.InsertCardInfo(Card.username, Card.card)
	if err != nil {
		fmt.Println(err)
	}

}

func Logout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)

	cookie = http.Cookie{
		Name:  "cart",
		Value: "",
	}

	http.SetCookie(w, &cookie)

	ctx := context.WithValue(r.Context(), "isAuthenticated", false)
	// Token is valid, proceed to the next handler

	http.Redirect(w, r.WithContext(ctx), "/home", http.StatusSeeOther)

}

func (db *Database) Login(w http.ResponseWriter, r *http.Request) {

	var c Creds
	c.username = r.FormValue("username")
	c.password = r.FormValue("password")

	log, _ := db.Auth(c)

	if log {

		claims := map[string]interface{}{
			"username": c.username,
		}

		_, tokenString, err := tokenAuth.Encode(claims)

		if err != nil {
			http.Error(w, "failed to generate jwt", http.StatusInternalServerError)
			return
		}

		cookie := http.Cookie{
			Name:     "jwt",
			Value:    tokenString,
			Expires:  time.Now().Add(time.Hour * 24),
			HttpOnly: true,
		}

		http.SetCookie(w, &cookie)

		ctx := context.WithValue(r.Context(), "isAuthenticated", true)
		// Token is valid, proceed to the next handler

		http.Redirect(w, r.WithContext(ctx), "/home", http.StatusSeeOther)
		return
	}

	fmt.Println("false")
	http.Error(w, "invalid creds", http.StatusUnauthorized)

}

func (db *Database) Register(w http.ResponseWriter, r *http.Request) {

	var c RegisterCreds
	c.username = r.FormValue("username")
	c.password = r.FormValue("password")
	c.password2 = r.FormValue("password2")

	if c.password != c.password2 || len(c.password) < 8 || !containsCapitalLetter(c.password) || !containsNumber(c.password) {
		http.Error(w, "invalid password", http.StatusBadRequest)
		return
	}

	err := db.InsertUser(c.username, c.password)
	if err != nil {
		http.Error(w, "failed to register user", http.StatusInternalServerError)
		return
	}

	// Redirect to the login page after successful registration
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Helper function to check if a string contains at least one capital letter
func containsCapitalLetter(s string) bool {
	for _, char := range s {
		if char >= 'A' && char <= 'Z' {
			return true
		}
	}
	return false
}

// Helper function to check if a string contains at least one number
func containsNumber(s string) bool {
	for _, char := range s {
		if char >= '0' && char <= '9' {
			return true
		}
	}
	return false
}

// function that checks for an error
func RenderError(t Template, err error) Template {
	if err != nil {
		panic(err)
	}
	return t
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extracting token from the cookie
		cookie, err := r.Cookie("jwt")

		isAuthenticated := false

		if err == nil {
			// Verifying the token
			_, err = jwtauth.VerifyToken(tokenAuth, cookie.Value)
			if err == nil {
				isAuthenticated = true
			}
		}

		ctx := context.WithValue(r.Context(), "isAuthenticated", isAuthenticated)
		next.ServeHTTP(w, r.WithContext(ctx))

	})
}

func Cart(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("jwt")
	action := r.FormValue("action")

	isAuthenticated := false

	if err == nil {

		_, err = jwtauth.VerifyToken(tokenAuth, cookie.Value)
		if err == nil {
			isAuthenticated = true
			switch {
			case action == "add_to_cart_product1":

				cartItems, err := r.Cookie("cart")
				if err != nil && err != http.ErrNoCookie {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				var existingCart []string
				if cartItems != nil {
					existingCart = strings.Split(cartItems.Value, ",")
				}

				updatedCart := append(existingCart, "product1")

				cookie := &http.Cookie{
					Name:  "cart",
					Value: strings.Join(updatedCart, ","),
				}
				http.SetCookie(w, cookie)

			case action == "add_to_cart_product2":

				cartItems, err := r.Cookie("cart")
				if err != nil && err != http.ErrNoCookie {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				var existingCart []string
				if cartItems != nil {
					existingCart = strings.Split(cartItems.Value, ",")
				}

				updatedCart := append(existingCart, "product2")

				cookie := &http.Cookie{
					Name:  "cart",
					Value: strings.Join(updatedCart, ","),
				}
				http.SetCookie(w, cookie)
			case action == "add_to_cart_product3":
				cartItems, err := r.Cookie("cart")
				if err != nil && err != http.ErrNoCookie {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				var existingCart []string
				if cartItems != nil {
					existingCart = strings.Split(cartItems.Value, ",")
				}

				updatedCart := append(existingCart, "product3")

				cookie := &http.Cookie{
					Name:  "cart",
					Value: strings.Join(updatedCart, ","),
				}
				http.SetCookie(w, cookie)

			default:
				fmt.Fprint(w, "Invalid action")
			}

			http.Redirect(w, r, "/home", http.StatusSeeOther)
		}
	}

	ctx := context.WithValue(r.Context(), "isAuthenticated", isAuthenticated)
	http.Redirect(w, r.WithContext(ctx), "/home", http.StatusSeeOther)

}

func main() {

	router := chi.NewRouter()

	db, err := InitDB()
	if err != nil {
		log.Fatal(err)
	}

	router.With(AuthMiddleware).Get("/basket", db.MainHandler(RenderError(Parse("templates/home2.html"))))
	router.With(AuthMiddleware).Post("/process_form", Cart)
	router.Get("/", Redirection)
	router.Get("/login", db.MainHandler(RenderError(Parse("templates/login.html"))))
	router.With(AuthMiddleware).Get("/home", db.MainHandler(RenderError(Parse("templates/home.html"))))
	router.Get("/register", db.MainHandler(RenderError(Parse("templates/register.html"))))
	router.Post("/register", db.Register)
	router.Post("/login", db.Login)
	router.Get("/logout", Logout)
	router.With(AuthMiddleware).Get("/checkout", db.MainHandler(RenderError(Parse("templates/checkout.html"))))
	router.Post("/checkout", db.Checkout)

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Page not found", http.StatusNotFound)
	})
	fmt.Println("Starting the server on :3000...")

	http.ListenAndServe(":3000", router)
}

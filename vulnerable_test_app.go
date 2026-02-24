// Intentionally Vulnerable Go Application
// DO NOT USE IN PRODUCTION

package main

import (
	"context"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
)

// ===============================
// Hardcoded secrets
// ===============================
var hardcodedPassword = "admin123"
var hardcodedToken = "SECRET_TOKEN_123"

// Hardcoded RSA Private Key
var hardcodedRSAKey = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALfakefakefakefakefakefakefakefakefakefakefakefake
-----END RSA PRIVATE KEY-----`

// Magic Number
const magicNumber = 1337

func main() {

	// Avoid binding to 0.0.0.0 (but we do it intentionally)
	http.HandleFunc("/", handler)
	http.ListenAndServe("0.0.0.0:8080", nil)

	// Unrecommended GOTO usage
	goto End

End:
	fmt.Println("End reached")
}

func handler(w http.ResponseWriter, r *http.Request) {

	// ===============================
	// Insecure Cookie (no HttpOnly, no Domain)
	// ===============================
	cookie := &http.Cookie{
		Name:  "sessionId",
		Value: "12345",
	}
	http.SetCookie(w, cookie)

	// Potential XSS
	input := r.URL.Query().Get("input")
	fmt.Fprintf(w, "<html>"+input+"</html>")

	// Unsafe Redirect
	redirectURL := r.URL.Query().Get("url")
	http.Redirect(w, r, redirectURL, 302)

	// Sensitive Data Exposure
	w.Write([]byte(os.Getenv("HOME")))
}

// ===============================
// Unsafe SQL generation + DB connection without timeout
// ===============================
func unsafeSQL(userInput string) {
	connStr := "root:" + hardcodedPassword + "@tcp(localhost:3306)/testdb"
	db, _ := sql.Open("mysql", connStr) // Unused error variable

	query := "SELECT * FROM users WHERE name = '" + userInput + "'"
	db.Query(query) // Resource leak (no close)
}

// ===============================
// Weak Hashing + Deprecated Algorithm
// ===============================
func weakHash(data string) {
	md5.Sum([]byte(data))
}

// ===============================
// Weak Random
// ===============================
func weakRandom() {
	mrand.Seed(time.Now().Unix())
	mrand.Intn(1000)
}

// ===============================
// Weak Encryption Mode + Small Key
// ===============================
func weakEncryption() {
	key := []byte("12345678") // Insecure key length
	block, _ := des.NewCipher(key) // Deprecated DES
	_ = block
}

// Non-random IV
func nonRandomIV() {
	iv := make([]byte, 16)
	fmt.Println(iv)
}

// ===============================
// Unsafe Code Execution
// ===============================
func unsafeExec(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

// ===============================
// Unsafe Path Handling + Hardcoded File Path
// ===============================
func unsafeFile(filename string) {
	path := "/tmp/" + filename
	ioutil.ReadFile(path)
}

// File creation without permissions
func createFile() {
	os.WriteFile("/tmp/test.txt", []byte("data"), 0777) // Improper permissions
}

// File deletion without checks
func deleteFile() {
	os.Remove("/tmp/old.txt")
}

// ===============================
// Potential SSRF
// ===============================
func ssrf(target string) {
	http.Get(target) // No validation, no timeout
}

// REST call without timeout
func restCall() {
	http.Get("http://example.com")
}

// Missing HTTP status code validation
func missingHTTPValidation() {
	resp, _ := http.Get("http://example.com")
	io.ReadAll(resp.Body)
}

// ===============================
// Ignoring SSL Hostname Verification + Weak SSL
// ===============================
func insecureTLS() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionSSL30,
		},
	}
	client := &http.Client{Transport: tr}
	client.Get("https://example.com")
}

// ===============================
// Unsafe Deserialization
// ===============================
func unsafeDeserialization(data []byte) {
	var obj interface{}
	json.Unmarshal(data, &obj)
}

// ===============================
// Unsafe LDAP Search
// ===============================
func unsafeLDAP(userInput string) {
	filter := "(cn=" + userInput + ")"
	fmt.Println(filter)
}

// ===============================
// Unsafe Reflection Use
// ===============================
func unsafeReflection(obj interface{}) {
	val := reflect.ValueOf(obj)
	fmt.Println(val)
}

// ===============================
// Unsafe XPath String (simulated)
// ===============================
func unsafeXPath(userInput string) {
	xpath := "//user[name='" + userInput + "']"
	fmt.Println(xpath)
}

// ===============================
// Potential XXE
// ===============================
func potentialXXE(xmlData string) {
	ioutil.ReadAll(strings.NewReader(xmlData))
}

// ===============================
// JWT Without Expiration
// ===============================
func jwtWithoutExp() {
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, _ := token.SignedString([]byte("secret"))
	fmt.Println(tokenString)
}

// ===============================
// Insecure Logging
// ===============================
func insecureLogging(password string) {
	log.Println("User password:", password)
}

// ===============================
// Improper Context Cancellation
// ===============================
func improperContext() {
	ctx, _ := context.WithCancel(context.Background())
	_ = ctx
}

// ===============================
// Potential Regex Injection
// ===============================
func regexInjection(userInput string) {
	regexp.MustCompile(userInput)
}

// ===============================
// Unsafe DB resource leak
// ===============================
func resourceLeak() {
	file, _ := os.Open("/tmp/test.txt")
	_ = file // Not closed
}

// ===============================
// Empty default case & Missing default
// ===============================
func switchExample(val int) {
	switch val {
	case 1:
		fmt.Println("One")
	default:
		// Empty default case
	}
}

func switchMissingDefault(val int) {
	switch val {
	case 1:
		fmt.Println("One")
	}
}

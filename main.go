// [© EmberLabs® (BY-SA) (Attribution, Share-alike)](https://emberlabs.tech/copyright/)
//
// - Similar to CC BY-SA
// - This license enables reusers to distribute, remix, adapt, and build upon the material in any medium or format, so long as attribution is given to the creator.
// - The license allows for commercial use.
// - If you remix, adapt, or build upon the material, you must license the modified material under identical terms.
// - A copy of the copyright license/terms must be retained as is in code or documents.
// - EmberLabs (BY-SA) includes the following elements:
//   - BY: Credit must be given to the creator.
//   - SA: Adaptations must be shared under the same terms.
//

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
)

var version = "1.2.0"
var prefix = ""
var verbose = 0

func main() {
	// Get the home dir, and attach the default 1passtoken file.
	home, err := os.UserHomeDir()
	if err != nil {
		println("Can not read home directory.")
		os.Exit(1)
	}
	tokenFile := home + "/.1passtoken"

	// Removed -user flag
	ver := flag.Bool("V", false, "Display version and quit")
	verb := flag.Bool("v", false, "Be verbose about translations")
	verb1 := flag.Bool("vv", false, "Be even more verbose about translations")
	tFile := flag.String("tokenfile", "", "Alternate token file to use.")
	pfx := flag.String("prefix", "", "A path prefix to be added at the start of all tag paths")
	ij := flag.String("injson", "", "Input JSON source file in case you do not want to use 1Password")
	pass := flag.String("token", "", "1Password Service Account token (optional; if empty, read from ~/.1passtoken)")
	vault := flag.String("vault", "", "1Password vault name")
	item := flag.String("item", "", "1Password item name or names as a CSV list (name1,name2,...) (source of JSON)")
	inFile := flag.String("in", "", "Input file path")
	outFile := flag.String("out", "", "Output file path")
	flag.Parse()

	// Version?
	if *ver {
		println("Version :", version)
		os.Exit(0)
	}
	// Verbose?
	if *verb {
		verbose = 1
	}
	if *verb1 {
		verbose = 2
	}
	// Alt token file specified?
	if *tFile != "" {
		tokenFile = *tFile
	}
	// A prefix has been specified? ( [[{nil|pfx.}path]] )
	if *pfx != "" {
		prefix = *pfx + "."
	}
	// If infile and outfile is missing, complain...
	if *inFile == "" || *outFile == "" {
		failf("missing required flags: -in <file> and -out <file> are required")
	}
	// If ij is not set, check for 1Pass items and if missing, complain.
	if *ij == "" && (*vault == "" || *item == "") {
		failf("missing required flags: -vault <name> and -item <name> are required for 1Password.")
	}

	// Decide token: use -token if provided; otherwise try ~/.1passtoken
	token := strings.TrimSpace(*pass)
	if token == "" {
		if t, err := readTokenFromHomeFile(tokenFile); err == nil && t != "" {
			token = t
		} else {
			fmt.Printf("Can not read the file %s\n", tokenFile)
			os.Exit(1)
		}
	}

	// Read input file
	input, err := os.ReadFile(*inFile)
	if err != nil {
		failf("failed to read input file: %v", err)
	}

	// If we read creds from the local file, ignore 1Pass.
	err = nil
	var itemJSON []byte

	if *ij != "" {
		itemJSON, err = os.ReadFile(*ij)
		if err != nil {
			failf("failed to read input JSON definition file: %v", err)
		}
		// Replace [[path]] occurrences with values from jsonPayload using gjson
		input = []byte(replaceTagsWithJSONValues(string(input), string(itemJSON)))
	} else {
		// If the vault is a, separated list of vaults process each one of them in order against the input.
		items := strings.Split(*item, ",")
		for _, itemName := range items {
			println("Processing", *vault, "/", itemName)
			// Retrieve 1Password item JSON via op CLI
			onePdata, e := fetchItemJSON(token, *vault, itemName)
			if e != nil {
				failf("failed to fetch 1Password item: %v", err)
			}
			onePjson, e := extractJSONField(onePdata)
			if e != nil {
				failf("failed to extract field \"json\" from 1Password item: %v", err)
			}
			itemJSON = []byte(onePjson)
			// Replace [[path]] occurrences with values from jsonPayload using gjson
			input = []byte(replaceTagsWithJSONValues(string(input), string(itemJSON)))
		}
	}

	// Write output file
	if err := os.WriteFile(*outFile, []byte(input), 0o644); err != nil {
		failf("failed to write output file: %v", err)
	}
}

// fetchItemJSON invokes the 1Password CLI to get an item in JSON form.
// For Service Accounts, token should be the OP_SERVICE_ACCOUNT_TOKEN.
func fetchItemJSON(token, vault, item string) ([]byte, error) {
	// Ensure op CLI exists
	if _, err := exec.LookPath("op"); err != nil {
		return nil, errors.New("1Password CLI 'op' not found on PATH")
	}

	cmd := exec.Command("op", "item", "get", "--vault", vault, "--format", "json", item)

	// In Service Account mode, token is provided as env var OP_SERVICE_ACCOUNT_TOKEN
	if token != "" {
		env := os.Environ()
		env = append(env, "OP_SERVICE_ACCOUNT_TOKEN="+token)
		cmd.Env = env
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("op item get failed: %s", msg)
	}

	return stdout.Bytes(), nil
}

// extractJSONField tries multiple likely locations to find a custom field named "json"
// in the item JSON returned by "op item get --format json".
// It returns the field's value as string.
func extractJSONField(opItemJSON []byte) (string, error) {
	// Try common locations for CLI v2:
	// 1) fields array with label "json"
	if v := gjson.GetBytes(opItemJSON, `fields.#(label=="json").value`); v.Exists() {
		return v.Array()[0].Str, nil
	}
	// 2) fields with id "json"
	if v := gjson.GetBytes(opItemJSON, `fields.#(id=="json").value`); v.Exists() {
		return v.Array()[0].Str, nil
	}
	// 3) sections[].fields[] with label "json"
	if v := gjson.GetBytes(opItemJSON, `sections.#.fields.#(label=="json").value`); v.Exists() && len(v.Array()) > 0 {
		return v.Array()[0].Str, nil
	}
	// 4) sometimes a note can hold JSON
	if v := gjson.GetBytes(opItemJSON, "notesPlain"); v.Exists() && looksLikeJSON(v.Str) {
		return v.Str, nil
	}

	return "", errors.New(`could not find a field named "json" in the item`)
}

// replaceTagsWithJSONValues finds [[path]] patterns and replaces them using gjson path queries into jsonPayload.
// If the path doesn't exist, the tag is left unchanged.
func replaceTagsWithJSONValues(input string, jsonPayload string) string {
	// Pre-validate JSON to avoid repeated parse if it's malformed
	if !gjson.Valid(jsonPayload) {
		// If not valid JSON, no replacements will be possible. Return as-is.
		println("Unable to parse input JSON.")
		os.Exit(1)
	}

	// Matches [[anything-but-brackets]] capturing the inner path in group 1
	re := regexp.MustCompile(`\[\[([^\[\]]+)\]\]`)

	// We need access to the captured group, so we can't just use ReplaceAllString.
	for _, loc := range re.FindAllStringSubmatch(input, -1) {
		tag := loc[0]
		path := loc[1]
		repval := ""
		mode := 0

		// ":" tag in the path? Want to inject a full JSON structure?
		if strings.Contains(loc[1], ":") {
			tparts := strings.SplitN(loc[1], ":", 2)
			path = tparts[1]
			switch tparts[0] {
			case "raw":
				mode = 1
			default:
			}
		}

		// Switch the modes here.
		val := gjson.Get(jsonPayload, prefix+path)
		switch mode {
		case 1:
			repval = val.Raw
		default:
			repval = val.Str
		}

		if val.Exists() {
			switch verbose {
			case 1:
				println("Translated    :", tag)
			case 2:
				println("Translated    :", tag, " --> ", repval)
			default:
			}
			input = strings.ReplaceAll(input, tag, repval)
		} else {
			switch verbose {
			case 1, 2:
				println("Not Translated:", tag)
			default:
			}
		}
	}

	return input
}

func looksLikeJSON(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Basic heuristic
	return (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) ||
		(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"))
}

func failf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// readTokenFromHomeFile reads a token from a file in the user's home directory.
// Returns the trimmed token or an error if the file can't be read.
func readTokenFromHomeFile(filename string) (string, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", errors.New("token file is empty")
	}
	return token, nil
}

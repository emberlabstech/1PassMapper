// [© EmberLabs® (BY-SA) (Attribution, Share-alike)](https://emberlabs.tech/copyright/)
//
// - Similar to CC BY-SA
// - This license enables re-users to distribute, remix, adapt, and build upon the material in any medium or format, so long as attribution is given to the creator.
// - The license allows for commercial use.
// - If you remix, adapt, or build upon the material, you must license the modified material under identical terms.
// - A copy of the copyright license/terms must be retained as is in code or documents.
// - EmberLabs (BY-SA) includes the following elements:
//   - BY: Credit must be given to the creator.
//   - SA: Adaptations must be shared under the same terms.
//

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/tidwall/gjson"
)

var version = "1.4.0"
var prefix = ""
var verbose = 0
var fieldName string // Json field name
var fieldType string // Json field name

func main() {
	// Get the home dir, and attach the default 1passtoken file.
	home, err := os.UserHomeDir()
	if err != nil {
		println("Can not read home directory.")
		os.Exit(1)
	}
	tokenFile := home + "/.1passtoken"

	ver := flag.Bool("version", false, "Display version and quit")
	ver1 := flag.Bool("V", false, "Display version and quit (alias)")
	verb := flag.Bool("v", false, "Be verbose about translations")
	fty := flag.Bool("fieldtypes", false, "List the field types")
	verb1 := flag.Bool("vv", false, "Be even more verbose about translations")
	tFile := flag.String("tokenfile", "", "Alternate token file to use.")
	pfx := flag.String("prefix", "", "A path prefix to be added at the start of all tag paths")
	ij := flag.String("injson", "", "Input JSON source file in case you do not want to use 1Password")
	pass := flag.String("token", "", "1Password Service Account token (optional; if empty, read from ~/.1passtoken)")
	vault := flag.String("vault", "", "1Password vault name")
	item := flag.String("item", "", "1Password item name or names as a CSV list (name1,name2,...) (source of JSON)")
	inFile := flag.String("in", "", "Input file path")
	outFile := flag.String("out", "", "Output file path")
	fieldCopy := flag.String("fieldcopy", "", "The field to be copied to the out file.")
	fieldName = *flag.String("fieldname", "json", "The field to use as source for json data (json)")
	fieldType = *flag.String("fieldtype", "Text", "The field type to use. (See -fieldtypes)")
	setValue := flag.String("setvalue", "", "Set the fieldName to the Value of setValue <string>")
	setFile := flag.String("setfile", "", "Set the fieldName to the Value of setFile <filename>")

	flag.Parse()

	if *fty {
		fmt.Println("Field types:")
		fmt.Println("Text, Concealed|Password, CreditCardType, CreditCardNumber, Phone, Url, Totp, Email, Reference, SshKey, Menu, MonthYear, Address, Date")
		os.Exit(0)
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

	if *setValue != "" && *setFile != "" {
		failf("Cannot specify both setValue and setFile")
		println("Value updated.")
		os.Exit(0)
	}

	// Set a value from file?
	if *setFile != "" {
		fi, err := os.Stat(*setFile)
		if os.IsNotExist(err) {
			failf("setFile %s does not exist", *setFile)
		}
		// Be reasonable here...
		if fi.Size() > 128*1024 {
			failf("File data too large - Max 128K")
		}
		// Read in the file contents.
		v, e := os.ReadFile(path.Clean(*setFile))
		if e != nil {
			failf("Failed to read file %s", *setFile)
		}
		if !setField(token, *vault, *item, fieldName, string(v)) {
			failf("Failed to set field")
		}
		println("Value updated.")
		os.Exit(0)
	}

	// Set a value?
	if *setValue != "" {
		if fieldName == "" {
			failf("fieldName must be specified when using setFile")
		}
		if !setField(token, *vault, *item, fieldName, *setValue) {
			failf("Failed to set field")
		}
		println("Value updated.")
		os.Exit(0)
	}

	// Version?
	if *ver || *ver1 {
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
	if *fieldCopy == "" && (*inFile == "" || *outFile == "") {
		failf("missing required flags: -in <file> and -out <file> are required")
	}
	// If ij is not set, check for 1Pass items and if missing, complain.
	if *ij == "" && (*vault == "" || *item == "") {
		failf("missing required flags: -vault <name> and -item <name> are required for 1Password.")
	}

	if *fieldCopy != "" && *vault != "" && *item != "" && *outFile != "" {
		fmt.Printf("Copying [%s:%s/%s] -> %s\n", *vault, *item, *fieldCopy, *outFile)
		if !fieldCopyData(token, *vault, *item, *fieldCopy, *outFile) {
			println("Error occurred. Could not copy the field.")
			os.Exit(1)
		}

		os.Exit(0)
	}

	// Let's do some work with the rest using input files.
	// ----------------------------------------------------------------------------
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
			onePdata, e := fetch1PItem(token, *vault, itemName)
			if e != nil {
				failf("failed to fetch 1Password item: %v for %s:%s", e, *vault, itemName)
			}

			onePjson, e := extract1PField(fieldName, onePdata)
			if e != nil {
				failf("failed to extract field \""+fieldName+"\" from 1Password item: %v", err)
			}
			itemJSON := string(onePjson)
			// Replace [[path]] occurrences with values from jsonPayload using gjson
			input = []byte(replaceTagsWithJSONValues(string(input), itemJSON))
		}
	}

	// Write output file
	if err := os.WriteFile(*outFile, []byte(input), 0o644); err != nil {
		failf("failed to write output file: %v", err)
	}
}

// fetch1PItem uses the 1Password Service Accounts SDK to fetch an item and return its JSON bytes.
func fetch1PItem(token, vault, item string) ([]byte, error) {
	fmt.Printf("Retreiving data from 1Pass for %s:%s\n", vault, item)

	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("fetch1PItem: empty token")
	}
	if verbose > 0 {
		fmt.Fprintf(os.Stderr, "fetch1PItem: vault=%q item=%q\n", vault, item)
	}

	ctx := context.Background()

	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("1PassMapper", version), // <-- required by SDK
	)
	if err != nil {
		return nil, fmt.Errorf("fetch1PItem: create 1Password client: %w", err)
	}

	// List vaults and find by Title (display name)
	if verbose > 1 {
		fmt.Fprintln(os.Stderr, "fetch1PItem: listing vaults")
	}
	vaults, err := client.Vaults().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch1PItem: list vaults: %w", err)
	}
	if len(vaults) == 0 {
		return nil, fmt.Errorf("fetch1PItem: no vaults visible to this token")
	}

	var vaultID string
	for _, v := range vaults {
		if verbose > 1 {
			fmt.Fprintf(os.Stderr, "fetch1PItem: seen vault ID=%s Title=%q\n", v.ID, v.Title)
		}
		if v.Title == vault {
			vaultID = v.ID
			break
		}
	}
	if vaultID == "" {
		return nil, fmt.Errorf("fetch1PItem: vault %q not found or not accessible", vault)
	}
	if verbose > 0 {
		fmt.Fprintf(os.Stderr, "fetch1PItem: using vaultID=%s for vault=%q\n", vaultID, vault)
	}

	// List items in that vault and find by Title
	if verbose > 1 {
		fmt.Fprintf(os.Stderr, "fetch1PItem: listing items in vaultID=%s\n", vaultID)
	}
	items, err := client.Items().List(ctx, vaultID)
	if err != nil {
		return nil, fmt.Errorf("fetch1PItem: list items in vault %q (id=%s): %w", vault, vaultID, err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("fetch1PItem: no items visible in vault %q (id=%s)", vault, vaultID)
	}

	var itemID string
	for _, it := range items {
		if verbose > 1 {
			fmt.Fprintf(os.Stderr, "fetch1PItem: seen item ID=%s Title=%q\n", it.ID, it.Title)
		}
		if it.Title == item {
			itemID = it.ID
			break
		}
	}
	if itemID == "" {
		return nil, fmt.Errorf("fetch1PItem: item %q not found in vault %q (id=%s)", item, vault, vaultID)
	}
	if verbose > 0 {
		fmt.Fprintf(os.Stderr, "fetch1PItem: using itemID=%s for item=%q\n", itemID, item)
	}

	// Get full item
	full, err := client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return nil, fmt.Errorf("fetch1PItem: get item %q (id=%s) in vault %q (id=%s): %w",
			item, itemID, vault, vaultID, err)
	}

	data, err := json.Marshal(full)
	if err != nil {
		return nil, fmt.Errorf("fetch1PItem: marshal item %q (id=%s): %w", item, itemID, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("fetch1PItem: marshaled item %q (id=%s) to empty JSON", item, itemID)
	}

	if verbose > 1 {
		fmt.Fprintf(os.Stderr, "fetch1PItem: successfully fetched item %q (id=%s)\n", item, itemID)
	}
	return data, nil
}

// extract1PField tries multiple likely locations to find a custom field named "json"
// in the item JSON returned by "op item get --format json".
// It returns the field's value as string.
func extract1PField(fieldName string, opItemJSON []byte) (string, error) {
	fieldList := MapRaw(string(opItemJSON), "fields")
	result := ""

	// Default value.
	if fieldName == "" {
		fieldName = "json"
	}

	// .fields: [ title: "json"? ]
	if gjson.Get(string(opItemJSON), "fields").Raw != "" {
		for _, field := range fieldList {
			println("Filename ", gjson.Get(field, "title").Str)
			if gjson.Get(field, "title").Str == fieldName {
				result = gjson.Get(field, "value").Str
			}
		}
	}

	if result != "" {
		return result, nil
	}

	return "", errors.New(`could not find a field named "` + fieldName + `" in the item`)
}

// replaceTagsWithJSONValues finds [[path]] patterns and replaces them using gjson path queries into jsonPayload.
// If the path doesn't exist, the tag is left unchanged.
func replaceTagsWithJSONValues(input string, jsonPayload string) string {
	// Pre-validate JSON to avoid repeated parse if it's malformed
	if !gjson.Valid(jsonPayload) {
		// If not valid JSON, no replacements will be possible. Return as-is.
		println("Unable to parse input JSON from 1Pass.")
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

// MapRaw - Get a Json subtree as a map
func MapRaw(json string, path string) map[string]string {
	vals := make(map[string]string, 0)

	result := gjson.Get(json, path)
	result.ForEach(func(k, v gjson.Result) bool {
		vals[k.String()] = v.Raw
		return true // keep iterating
	})

	return vals
}

// fieldCopyData retrieves and extracts a specific field from a 1Password item and writes it to an output file.
// Returns true if the operation succeeds, otherwise false.
func fieldCopyData(token, vault, item, field, outFile string) bool {
	onePdata, e := fetch1PItem(token, vault, item)
	if e != nil {
		failf("failed to fetch 1Password item: %v for %s:%s", e, vault, item)
		return false
	}

	fmt.Printf("onePData : \n%s\n%v\n\n", onePdata)

	fieldData, e := extract1PField(field, onePdata)
	if e != nil {
		failf("failed to extract field \"%s\" from 1Password item: %v", field, e)
		return false
	}
	os.WriteFile(outFile, []byte(fieldData), 0666)
	return true
}

// setField updates or creates a field in a specified 1Password item within a given vault and returns success as a boolean.
func setField(token, vault, item, field, value string) bool {
	ctx := context.Background()

	token = strings.TrimSpace(token)
	vault = strings.TrimSpace(vault)
	item = strings.TrimSpace(item)
	field = strings.TrimSpace(field)

	ft := "Text"
	switch fieldType {
	case "Text", "Concealed", "CreditCardType", "CreditCardNumber", "Phone", "Url", "Totp", "Email", "Reference", "SshKey", "Menu", "MonthYear", "Address", "Date":
		ft = fieldType
	case "Password":
		ft = "Concealed"
	default:
		failf("setField: invalid field type: %s", fieldType)
		return false
	}

	if verbose > 0 {
		println("Vault      :", vault)
		println("Item       :", item)
		println("Field name :", ft, ":", field)
	}

	if token == "" || vault == "" || item == "" || field == "" {
		fmt.Fprintln(os.Stderr, "setField: token, vault, item, and field are required")
		return false
	}

	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("1PassMapper", version),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setField: create 1Password client: %v\n", err)
		return false
	}

	// Resolve vault title -> vaultID
	vaults, err := client.Vaults().List(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setField: list vaults: %v\n", err)
		return false
	}
	var vaultID string
	for _, v := range vaults {
		if v.Title == vault {
			vaultID = v.ID
			break
		}
	}
	if vaultID == "" {
		fmt.Fprintf(os.Stderr, "setField: vault %q not found or not accessible\n", vault)
		return false
	}

	// Resolve item title -> itemID
	items, err := client.Items().List(ctx, vaultID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setField: list items in vault %q: %v\n", vault, err)
		return false
	}
	var itemID string
	for _, it := range items {
		if it.Title == item {
			itemID = it.ID
			break
		}
	}
	if itemID == "" {
		fmt.Fprintf(os.Stderr, "setField: item %q not found in vault %q\n", item, vault)
		return false
	}

	// Get full item (SDK returns a value, not a pointer)
	full, err := client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setField: get item %q: %v\n", item, err)
		return false
	}

	// Update existing field (match by Title), otherwise append a new custom field.
	updated := false
	for i := range full.Fields {
		if strings.EqualFold(strings.TrimSpace(full.Fields[i].Title), field) {
			full.Fields[i].Value = value
			updated = true
			break
		}
	}

	// Ensure all field IDs are present & unique ("" duplicates are a common culprit).
	usedIDs := make(map[string]struct{}, len(full.Fields))
	for i := range full.Fields {
		id := strings.TrimSpace(full.Fields[i].ID)
		if id == "" {
			id = newItemID()
			full.Fields[i].ID = id
		}
		if _, exists := usedIDs[id]; exists {
			id = newItemID()
			full.Fields[i].ID = id
		}
		usedIDs[id] = struct{}{}
	}

	if !updated {
		full.Fields = append(full.Fields, onepassword.ItemField{
			ID:        newItemID(),
			Title:     field,
			FieldType: onepassword.ItemFieldType(ft),
			Value:     value,
		})
	}

	// Put expects (ctx, item)
	_, err = client.Items().Put(ctx, full)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setField: put item %q: %v\n", item, err)
		return false
	}

	if verbose > 0 {
		fmt.Fprintf(os.Stderr, "setField: %s:%s updated field %q\n", vault, item, field)
	}
	return true
}

// newItemID generates a unique 32-character hexadecimal string by encoding 16 random bytes.
func newItemID() string {
	// 16 bytes => 32 hex chars. Good enough for uniqueness in an item.
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

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
	"flag"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
)

var version = "r.m.b"
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
			switch strings.ToLower(tparts[0]) {
			case "raw", "r":
				mode = 1
			default:
			}
		}

		// Switch the modes here.
		val := gjson.Result{}
		// If global, get it from the global namespace and ignore the prefix.
		// This allows common settings across prefixes without duplication.
		if strings.HasPrefix(path, "global.") {
			val = gjson.Get(jsonPayload, path)
		} else {
			val = gjson.Get(jsonPayload, prefix+path)
		}
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

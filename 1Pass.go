package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	
	"github.com/1password/onepassword-sdk-go"
	"github.com/tidwall/gjson"
)

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

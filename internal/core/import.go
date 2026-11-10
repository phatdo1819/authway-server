package core

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/phatdo1819/authway-server/internal/secret"
	"github.com/phatdo1819/authway-server/internal/store"
)

// The import of users from a CSV file, made with a spreadsheet: each row adds a user, as Add user does. The peers are
// given to the users afterwards, on their servers. The file is checked whole, and imported whole in one transaction,
// or not at all.

const (
	MaxImportRows  = 500
	MaxImportBytes = 512 << 10
)

// importColumns are the names of the columns in the header of the file, written as the spreadsheets of people do:
// in any case, with spaces or dashes. Any other name is refused: a mistyped password column must not make the
// server choose the passwords without a word.
var importColumns = map[string]string{
	"username":     "username",
	"user":         "username",
	"full_name":    "full_name",
	"fullname":     "full_name",
	"display_name": "full_name",
	"name":         "full_name",
	"password":     "password",
}

// ImportInput is the text of a CSV file. With Check, the file is only checked: nothing is added. With SkipExisting,
// the rows of users already there are skipped instead of refused: those users don't change, their passwords neither.
type ImportInput struct {
	CSV          string `json:"csv"`
	Check        bool   `json:"check"`
	SkipExisting bool   `json:"skip_existing"`
}

// ImportRow is the user a row of the file adds, or why it can't.
type ImportRow struct {
	// the line of the row in the file, from 1 for the header
	Line     int    `json:"line"`
	Username string `json:"username"`
	FullName string `json:"full_name"`
	// "given", or "generated" when the file has none; "" for a row skipped
	Password string `json:"password"`
	// a user already there, with SkipExisting: the row adds and changes nothing
	Skipped bool `json:"skipped,omitempty"`
	// by column, what's wrong: the codes of ValidationError; "row" for the row itself
	Errors map[string]string `json:"errors,omitempty"`
}

// ImportResult is the file checked, or imported.
type ImportResult struct {
	Rows []ImportRow `json:"rows"`
	// the users the file adds, and the rows skipped
	Users   int `json:"users"`
	Skipped int `json:"skipped"`
	// the rows with an error: nothing is imported until there are none
	Invalid  int  `json:"invalid"`
	Imported bool `json:"imported"`
	// the passwords made for the users without one in the file, shown this once
	Passwords []ImportedPassword `json:"passwords,omitempty"`
}

type ImportedPassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// importLine is a row of the file that isn't empty: its cells by column.
type importLine struct {
	line  int
	cells map[string]string
	// cells past the columns of the header
	extra bool
}

type importPlan struct {
	rows    []ImportRow
	invalid int
}

func (p *importPlan) result() *ImportResult {
	result := &ImportResult{Rows: p.rows, Invalid: p.invalid}
	for _, row := range p.rows {
		if row.Skipped {
			result.Skipped++
		} else {
			result.Users++
		}
	}
	return result
}

// Import checks a CSV file of users, and without Check adds them all, or none when a row is wrong. The passwords that
// the file doesn't give are made here and answered once.
func (s *Service) Import(by Actor, input ImportInput) (*ImportResult, error) {
	lines, err := parseImport(input.CSV)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	plan, err := s.planImportLocked(lines, input.SkipExisting)
	policy := s.policyLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if input.Check || plan.invalid > 0 {
		return plan.result(), nil
	}
	// the password of a row: the one of the file, or one made once for its user
	made := map[string]string{}
	passwordOf := func(index int, row ImportRow) string {
		if password := lines[index].cells["password"]; password != "" {
			return password
		}
		key := strings.ToLower(row.Username)
		if made[key] == "" {
			made[key] = newPassword(policy, row.Username)
		}
		return made[key]
	}
	// the hashes take time: out of the lock, as many at once as the hash allows
	passwords := map[string]string{}
	for index, row := range plan.rows {
		if !row.Skipped {
			passwords[strings.ToLower(row.Username)] = passwordOf(index, row)
		}
	}
	hashes, err := hashAll(passwords)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// another administrator may have added or deleted a user meanwhile: checked again
	if plan, err = s.planImportLocked(lines, input.SkipExisting); err != nil {
		return nil, err
	}
	if plan.invalid > 0 {
		return plan.result(), nil
	}
	var added []ImportRow
	for index, row := range plan.rows {
		if row.Skipped {
			continue
		}
		key := strings.ToLower(row.Username)
		if _, ok := hashes[key]; !ok {
			// skipped at the first check, deleted since: added now
			hash, err := secret.HashPassword(passwordOf(index, row))
			if err != nil {
				return nil, err
			}
			hashes[key] = hash
		}
		added = append(added, row)
	}
	if len(added) > 0 {
		now := s.now().Unix()
		err = s.db.Tx(func(tx *store.Tx) error {
			for _, row := range added {
				user := &store.User{Username: row.Username, FullName: row.FullName,
					PasswordHash: hashes[strings.ToLower(row.Username)], CreatedAt: now, UpdatedAt: now, UpdatedBy: by.Username}
				if err := tx.CreateUser(user); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, takenOr(err, "username")
		}
	}
	result := plan.result()
	result.Imported = true
	s.log.Info("users imported", "users", result.Users, "skipped", result.Skipped, "by", by.Username)
	for _, row := range added {
		s.changeLocked(by, store.Event{Kind: "user_added", Username: row.Username, Detail: "imported"})
		if password, ok := made[strings.ToLower(row.Username)]; ok {
			result.Passwords = append(result.Passwords, ImportedPassword{Username: row.Username, Password: password})
		}
	}
	return result, nil
}

// parseImport reads the rows of a CSV file. Its header names the columns, in any order; the empty rows are skipped.
// The separator is the one of the header: a comma, a semicolon (the spreadsheets of the countries with a decimal
// comma) or a tab.
func parseImport(text string) ([]importLine, error) {
	fail := func(code, detail string) error {
		return &ValidationError{Fields: map[string]string{"csv": code}, Detail: detail}
	}
	if len(text) > MaxImportBytes {
		return nil, fail("too_large", "")
	}
	// the byte order mark of the UTF-8 files of Excel
	text = strings.TrimPrefix(text, string(rune(0xfeff)))
	if !utf8.ValidString(text) {
		return nil, fail("not_utf8", "")
	}
	reader := csv.NewReader(strings.NewReader(text))
	reader.Comma = separatorOf(text)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	header, err := reader.Read()
	if errors.Is(err, io.EOF) {
		return nil, fail("empty", "")
	}
	if err != nil {
		return nil, fail("invalid", err.Error())
	}
	columns := make([]string, len(header))
	seen := map[string]bool{}
	for index, name := range header {
		name = strings.TrimSpace(name)
		if name == "" {
			// an empty column, as spreadsheets leave at the end
			continue
		}
		column, ok := importColumns[columnKey(name)]
		switch {
		case !ok:
			return nil, fail("unknown_column", name)
		case seen[column]:
			return nil, fail("duplicate_column", name)
		}
		seen[column] = true
		columns[index] = column
	}
	if !seen["username"] {
		return nil, fail("no_username", "")
	}
	var lines []importLine
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fail("invalid", err.Error())
		}
		line, _ := reader.FieldPos(0)
		entry := importLine{line: line, cells: map[string]string{}}
		empty := true
		for index, value := range record {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			empty = false
			if index >= len(columns) || columns[index] == "" {
				entry.extra = true
				continue
			}
			entry.cells[columns[index]] = value
		}
		if empty {
			continue
		}
		if len(lines) == MaxImportRows {
			return nil, fail("too_many_rows", "")
		}
		lines = append(lines, entry)
	}
	if len(lines) == 0 {
		return nil, fail("no_rows", "")
	}
	return lines, nil
}

// separatorOf returns the separator of the cells: the one the first line has most of
func separatorOf(text string) rune {
	first, _, _ := strings.Cut(text, "\n")
	best, count := ',', strings.Count(first, ",")
	for _, other := range []rune{';', '\t'} {
		if n := strings.Count(first, string(other)); n > count {
			best, count = other, n
		}
	}
	return best
}

// columnKey writes the name of a column as importColumns has it: lowercase, with underscores
func columnKey(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return '_'
		}
		return r
	}, name)
}

// planImportLocked checks every row as Add user does, and against the users of now and the rows before it. With
// skipExisting, a row of a user already there is skipped, whatever its other cells say: it changes nothing.
func (s *Service) planImportLocked(lines []importLine, skipExisting bool) (*importPlan, error) {
	users, err := s.db.Q().Users()
	if err != nil {
		return nil, err
	}
	policy := s.policyLocked()
	// the usernames don't count their case, as in the database
	taken := map[string]bool{}
	for _, user := range users {
		taken[strings.ToLower(user.Username)] = true
	}
	inFile := map[string]bool{}
	plan := &importPlan{}
	for _, line := range lines {
		username, fullName, password := line.cells["username"], line.cells["full_name"], line.cells["password"]
		key := strings.ToLower(username)
		if skipExisting && username != "" && taken[key] {
			plan.rows = append(plan.rows, ImportRow{Line: line.line, Username: username, FullName: fullName, Skipped: true})
			continue
		}
		row := ImportRow{Line: line.line, Username: username, FullName: fullName, Password: "generated"}
		if password != "" {
			row.Password = "given"
		}
		var c checks
		if line.extra {
			c.fail("row", "extra_cells")
		}
		switch {
		case username == "":
			c.fail("username", "required")
		case !usernamePattern.MatchString(username):
			c.fail("username", "invalid")
		case taken[key]:
			// an import adds users, it never changes one
			c.fail("username", "taken")
		case inFile[key]:
			c.fail("username", "twice")
		}
		inFile[key] = true
		if !validFullName(fullName) {
			c.fail("full_name", "invalid")
		}
		if password != "" {
			if code := policy.check(password, username, 0); code != "" {
				c.fail("password", code)
			}
		}
		row.Errors = c.fields
		if len(c.fields) > 0 {
			plan.invalid++
		}
		plan.rows = append(plan.rows, row)
	}
	return plan, nil
}

// hashAll hashes passwords, by key: the hash runs two at a time, the others wait their turn.
func hashAll(passwords map[string]string) (map[string]string, error) {
	var wait sync.WaitGroup
	var mu sync.Mutex
	hashes := make(map[string]string, len(passwords))
	var failed error
	for key, password := range passwords {
		wait.Add(1)
		go func() {
			defer wait.Done()
			hash, err := secret.HashPassword(password)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = err
				return
			}
			hashes[key] = hash
		}()
	}
	wait.Wait()
	return hashes, failed
}

// newPassword makes a password that follows the policy: 16 characters at least, easy to read and to type, with a
// letter of each case, a digit and a symbol, as the web UI makes them.
func newPassword(policy PasswordPolicy, username string) string {
	const (
		lower   = "abcdefghjkmnpqrstuvwxyz"
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		digits  = "23456789"
		symbols = "-_.!?#%+="
	)
	length := max(16, policy.MinLength)
	for {
		chars := []byte{pick(lower), pick(upper), pick(digits), pick(symbols)}
		for len(chars) < length {
			chars = append(chars, pick(lower+upper+digits))
		}
		for index := len(chars) - 1; index > 0; index-- {
			other := below(index + 1)
			chars[index], chars[other] = chars[other], chars[index]
		}
		// never a symbol first: a spreadsheet reads a cell that starts with = + or - as a formula, and the web UI
		// gives these passwords in a CSV file
		if strings.IndexByte(symbols, chars[0]) >= 0 {
			chars[0], chars[1] = chars[1], chars[0]
		}
		if password := string(chars); policy.check(password, username, 0) == "" {
			return password
		}
	}
}

func pick(set string) byte {
	return set[below(len(set))]
}

// below returns a random number from 0 to n-1, each as likely
func below(n int) int {
	limit := (1 << 32) / uint64(n) * uint64(n)
	var data [4]byte
	for {
		if _, err := rand.Read(data[:]); err != nil {
			// the system has no randomness left: nothing safe can go on
			panic(err)
		}
		if value := uint64(binary.BigEndian.Uint32(data[:])); value < limit {
			return int(value % uint64(n))
		}
	}
}

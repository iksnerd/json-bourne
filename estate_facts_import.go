package jb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/iksnerd/json-bourne/internal/casefile"
)

// EstateFactsImportNote travels with every result of [EstateFactsImport].
const EstateFactsImportNote = "Imported facts are observations by a store someone else built (source scan-cache), as the operator's export " +
	"states them. They are not proof, and the viewer shows each with its source and time. Nothing was sent anywhere: the import file was read from disk."

// EstateFactsImportOptions are the options of [EstateFactsImport].
type EstateFactsImportOptions struct {
	// EstateOptions.File is the estate file the facts are added to. Its nodes must
	// already exist; an import never creates one.
	EstateOptions
	// Apply writes the file. The zero value is a dry run: the import is read and checked,
	// the result says what would be added, and nothing is changed.
	Apply bool
}

// EstateFactsImportResult is the account of one [EstateFactsImport] run.
type EstateFactsImportResult struct {
	Note string
	// File is the estate file, relative to the case directory.
	File string
	// Import is the import file as it was named.
	Import string
	// Source is the source role of every imported fact: "scan-cache".
	Source string
	// Method is the method string the facts carry: the import's method and source note.
	Method string
	// Entries is the number of (node, key) entries in the import file, and Facts the
	// number of facts (values) in it.
	Entries, Facts int
	// Added is how many facts are new to the estate file, and Unchanged how many were
	// already recorded (same key, value, source and method) and were left as they are.
	Added, Unchanged int
	// Applied is true only when the file was written.
	Applied bool
}

// MarshalJSON prints what `jb estate facts import --output json` prints.
func (r EstateFactsImportResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Note      string `json:"note"`
		File      string `json:"file"`
		Import    string `json:"import"`
		Source    string `json:"source"`
		Method    string `json:"method"`
		Entries   int    `json:"entries"`
		Facts     int    `json:"facts"`
		Added     int    `json:"added"`
		Unchanged int    `json:"unchanged"`
		Applied   bool   `json:"applied"`
	}{r.Note, r.File, r.Import, r.Source, r.Method, r.Entries, r.Facts, r.Added, r.Unchanged, r.Applied})
}

// EstateFactsImport reads one small import file (docs/CASE-SPEC.md section 4.5.2: a JSON
// object with the method, a source note, an observed time and, per node and key, a list
// of values) and adds its facts to an estate file, as `jb estate facts import` does. It
// reads the one file and nothing else: it never contacts the network, and it needs no
// `estate.external` switch because nothing leaves the machine. Every fact has the source
// `scan-cache`.
//
// The call is a dry run unless opts.Apply is set. The whole import is refused, and the
// estate file is left as it was, when the import file has an unknown key, is larger than
// [casefile.MaxFactsImportSize] bytes or holds more than [casefile.MaxFactsImportFacts]
// facts, names a node the estate file does not have, or would leave a file that does not
// load (more than 50 facts on a node, for example). Those are usage errors. A fact that
// is already recorded is left as it is, so importing the same export twice changes
// nothing the second time. Rewriting the file does not preserve comments.
func EstateFactsImport(caseDir, importFile string, opts EstateFactsImportOptions) (*EstateFactsImportResult, error) {
	if caseDir == "" {
		return nil, usagef("a case directory is required")
	}
	if importFile == "" {
		return nil, usagef("name the import file")
	}
	file := opts.file()
	if err := checkEstateFile(file); err != nil {
		return nil, err
	}
	data, err := readImportFile(importFile)
	if err != nil {
		return nil, err
	}
	imp, err := casefile.ParseFactsImport(data)
	if err != nil {
		return nil, usagef("import file %s: %v", importFile, err)
	}
	c, err := loadEstateCase(caseDir)
	if err != nil {
		return nil, err
	}
	base, err := casefile.LoadEstateFile(c, file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, usagef("estate file %s does not exist: an import adds facts to nodes that were recorded first (see `jb estate`)", file)
	case err != nil:
		return nil, fmt.Errorf("%w", err)
	}
	merged, res, err := casefile.ApplyFactsImport(base, imp)
	if err != nil {
		return nil, usagef("import file %s: %v", importFile, err)
	}
	out := &EstateFactsImportResult{Note: EstateFactsImportNote, File: c.Paths.Estate + "/" + file, Import: importFile,
		Source: casefile.FactsImportSource, Method: imp.Method + " (source: " + imp.SourceNote + ")",
		Entries: len(imp.Facts), Facts: imp.Count(), Added: res.Added, Unchanged: res.Unchanged}
	if opts.Apply && res.Added > 0 {
		if err := casefile.SaveEstateFile(c, file, merged); err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		out.Applied = true
	}
	return out, nil
}

// readImportFile reads at most casefile.MaxFactsImportSize bytes of a regular file and
// refuses a larger one. It is the only read an import makes besides the estate file.
func readImportFile(path string) ([]byte, error) {
	fh, err := os.Open(path) // #nosec G304 -- the operator names the file they obtained
	if err != nil {
		return nil, usagef("import file: %v", err)
	}
	defer fh.Close()
	if st, err := fh.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, usagef("import file %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(fh, casefile.MaxFactsImportSize+1))
	if err != nil {
		return nil, fmt.Errorf("read import file %s: %w", path, err)
	}
	if len(data) > casefile.MaxFactsImportSize {
		return nil, usagef("import file %s is larger than %d bytes", path, casefile.MaxFactsImportSize)
	}
	return data, nil
}

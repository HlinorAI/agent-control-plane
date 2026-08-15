package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	defaultMaxBytes = 256 << 10
	maxDepth        = 32
	maxEntries      = 2048
	maxStringBytes  = 64 << 10
)

var (
	errLimit       = errors.New("payload limit exceeded")
	errMalformed   = errors.New("malformed JSON payload")
	secretKeyRE    = regexp.MustCompile(`(?i)(api[_-]?key|authorization|bearer|private[_-]?key|password|secret|token|credential)`)
	dangerousCmdRE = regexp.MustCompile(`(?i)(^|[\s/])(?:sh|bash|zsh|fish|cmd|powershell|python|python3|perl|ruby|node|curl|wget|nc|netcat|socat|rm|touch|chmod|chown|docker|kubectl)(?:\s|$)`)
	secretValueRE  = regexp.MustCompile(`(?i)(sk-[a-z0-9]{12,}|bearer\s+[a-z0-9._-]{12,}|-----begin|gh[pousr]_[a-z0-9_]{20,}|xox[baprs]-[a-z0-9-]{10,})`)
)

type violation struct {
	File   string `json:"file"`
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

type report struct {
	Root               string      `json:"root"`
	Files              int         `json:"files"`
	Checked            int         `json:"checked"`
	BlockingViolations int         `json:"blocking_violations"`
	Violations         []violation `json:"violations"`
}

func main() {
	fs := flag.NewFlagSet("fuzzpayloadcheck", flag.ExitOnError)
	root := fs.String("root", "internal/runtimefuzz/testdata/fuzz", "directory containing JSON fuzz payloads")
	maxBytes := fs.Int64("max-bytes", defaultMaxBytes, "maximum payload size in bytes")
	allowAdversarial := fs.Bool("allow-adversarial", false, "allow expected negative-case policy violations while keeping safety violations blocking")
	fs.Parse(os.Args[1:])

	result, err := validateRootWithOptions(*root, *maxBytes, *allowAdversarial)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fuzzpayloadcheck: %v\n", err)
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "fuzzpayloadcheck: encode report: %v\n", err)
		os.Exit(2)
	}
	if result.BlockingViolations > 0 {
		os.Exit(1)
	}
}

func validateRoot(root string, maxBytes int64) (report, error) {
	return validateRootWithOptions(root, maxBytes, false)
}

func validateRootWithOptions(root string, maxBytes int64, allowAdversarial bool) (report, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return report{}, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return report{}, err
	}
	if !info.IsDir() {
		return report{}, fmt.Errorf("root is not a directory: %s", root)
	}
	if maxBytes <= 0 {
		return report{}, fmt.Errorf("max-bytes must be positive")
	}

	result := report{Root: abs}
	err = filepath.WalkDir(abs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			result.Violations = append(result.Violations, violation{File: path, Code: "walk_error", Detail: walkErr.Error()})
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		result.Files++
		if entry.Type()&os.ModeSymlink != 0 {
			result.Violations = append(result.Violations, violation{File: path, Code: "symlink", Path: "$", Detail: "symlink payloads are not allowed"})
			return nil
		}
		if !entry.Type().IsRegular() {
			result.Violations = append(result.Violations, violation{File: path, Code: "unsupported_file", Path: "$", Detail: "only regular payload files are allowed"})
			return nil
		}
		if !supportedPayload(path) {
			return nil
		}
		result.Checked++
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			result.Violations = append(result.Violations, violation{File: path, Code: "read_error", Detail: "payload could not be read"})
			return nil
		}
		result.Violations = append(result.Violations, validatePayload(path, data, maxBytes)...)
		return nil
	})
	if err != nil {
		return report{}, err
	}
	sort.Slice(result.Violations, func(i, j int) bool {
		if result.Violations[i].File != result.Violations[j].File {
			return result.Violations[i].File < result.Violations[j].File
		}
		if result.Violations[i].Code != result.Violations[j].Code {
			return result.Violations[i].Code < result.Violations[j].Code
		}
		return result.Violations[i].Path < result.Violations[j].Path
	})
	for _, item := range result.Violations {
		if !allowAdversarial || !isExpectedAdversarialViolation(item.Code) {
			result.BlockingViolations++
		}
	}
	return result, nil
}

func isExpectedAdversarialViolation(code string) bool {
	switch code {
	case "dangerous_command", "unsafe_url", "unsafe_character", "malformed_json", "multiple_values", "duplicate_key":
		return true
	default:
		return false
	}
}

func supportedPayload(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".json" || ext == ".yaml" || ext == ".yml" || ext == ".jsonl"
}

func validatePayload(file string, data []byte, maxBytes int64) []violation {
	add := func(code, path, detail string) violation {
		return violation{File: file, Code: code, Path: path, Detail: detail}
	}
	var out []violation
	if int64(len(data)) > maxBytes {
		return []violation{add("size_limit", "$", fmt.Sprintf("payload is %d bytes; limit is %d", len(data), maxBytes))}
	}
	if !utf8.Valid(data) {
		return []violation{add("invalid_utf8", "$", "payload is not valid UTF-8")}
	}
	if bytes.IndexByte(data, 0) >= 0 {
		out = append(out, add("nul_byte", "$", "NUL byte is not allowed"))
	}
	if !isSyntheticPath(file) {
		out = append(out, add("unsafe_path", "$", "payload must be under an approved synthetic seed path"))
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, parseViolations := parseValue(decoder, "$", 0, file)
	out = append(out, parseViolations...)
	if value == nil && len(parseViolations) == 0 {
		out = append(out, add("empty_payload", "$", "payload has no JSON value"))
		return out
	}
	if err := requireSingleValue(decoder); err != nil {
		out = append(out, add("multiple_values", "$", "payload must contain exactly one JSON value"))
	}
	return out
}

func parseValue(decoder *json.Decoder, path string, depth int, file string) (any, []violation) {
	add := func(code, detail string) violation {
		return violation{File: file, Code: code, Path: path, Detail: detail}
	}
	if depth > maxDepth {
		return nil, []violation{add("depth_limit", fmt.Sprintf("maximum depth is %d", maxDepth))}
	}
	token, err := decoder.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, []violation{add("malformed_json", "unexpected end of payload")}
		}
		return nil, []violation{add("malformed_json", "JSON token could not be decoded")}
	}
	switch start := token.(type) {
	case json.Delim:
		switch start {
		case '{':
			return parseObject(decoder, path, depth, file)
		case '[':
			return parseArray(decoder, path, depth, file)
		default:
			return nil, []violation{add("malformed_json", "unexpected closing delimiter")}
		}
	case string:
		violations := validateString([]byte(start), path, file)
		return start, violations
	case json.Number:
		return start, nil
	case bool, nil:
		return start, nil
	default:
		return nil, []violation{add("malformed_json", "unsupported JSON token")}
	}
}

func parseObject(decoder *json.Decoder, path string, depth int, file string) (map[string]any, []violation) {
	var out []violation
	object := map[string]any{}
	seen := map[string]bool{}
	entries := 0
	for decoder.More() {
		entries++
		if entries > maxEntries {
			out = append(out, violation{File: file, Code: "entry_limit", Path: path, Detail: fmt.Sprintf("maximum entries is %d", maxEntries)})
			return object, out
		}
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			out = append(out, violation{File: file, Code: "malformed_json", Path: path, Detail: "object key is not a string"})
			return object, out
		}
		keyPath := path + "." + key
		if seen[key] {
			out = append(out, violation{File: file, Code: "duplicate_key", Path: keyPath, Detail: "duplicate object key"})
		}
		seen[key] = true
		value, violations := parseValue(decoder, keyPath, depth+1, file)
		out = append(out, violations...)
		object[key] = value
		out = append(out, validateFieldPolicy(key, value, keyPath, file)...)
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		out = append(out, violation{File: file, Code: "malformed_json", Path: path, Detail: "object is not closed"})
	}
	return object, out
}

func parseArray(decoder *json.Decoder, path string, depth int, file string) ([]any, []violation) {
	var out []violation
	array := []any{}
	for index := 0; decoder.More(); index++ {
		if index >= maxEntries {
			out = append(out, violation{File: file, Code: "entry_limit", Path: path, Detail: fmt.Sprintf("maximum entries is %d", maxEntries)})
			return array, out
		}
		itemPath := fmt.Sprintf("%s[%d]", path, index)
		value, violations := parseValue(decoder, itemPath, depth+1, file)
		out = append(out, violations...)
		array = append(array, value)
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim(']') {
		out = append(out, violation{File: file, Code: "malformed_json", Path: path, Detail: "array is not closed"})
	}
	return array, out
}

func validateFieldPolicy(key string, value any, path, file string) []violation {
	var out []violation
	add := func(code, detail string) {
		out = append(out, violation{File: file, Code: code, Path: path, Detail: detail})
	}
	lowerKey := strings.ToLower(key)
	if secretKeyRE.MatchString(lowerKey) {
		if text, ok := value.(string); ok && !isSyntheticSecret(text) {
			add("secret_like_value", "secret-like field is not explicitly synthetic")
		}
	}
	if text, ok := value.(string); ok {
		if strings.Contains(lowerKey, "command") || lowerKey == "args" {
			if dangerousCmdRE.MatchString(text) || strings.ContainsAny(text, ";&|$`()") {
				add("dangerous_command", "command/argument contains shell or execution material")
			}
		}
		if strings.Contains(lowerKey, "url") || lowerKey == "endpoint" {
			if !isApprovedSeedURL(text) {
				add("unsafe_url", "URL is not an approved synthetic endpoint")
			}
		}
	}
	return out
}

func validateString(value []byte, path, file string) []violation {
	var out []violation
	if len(value) > maxStringBytes {
		out = append(out, violation{File: file, Code: "string_limit", Path: path, Detail: fmt.Sprintf("maximum string size is %d", maxStringBytes)})
	}
	for _, r := range string(value) {
		if r < 0x20 || r == '\u202e' || r == '\u202d' || r == '\u202c' {
			out = append(out, violation{File: file, Code: "unsafe_character", Path: path, Detail: "control or bidi character is not allowed in CI seed"})
			break
		}
	}
	if secretValueRE.Match(value) && !isSyntheticSecret(string(value)) {
		out = append(out, violation{File: file, Code: "secret_like_value", Path: path, Detail: "value resembles a real credential"})
	}
	return out
}

func requireSingleValue(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return errors.New("trailing malformed JSON")
}

func isSyntheticSecret(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "SYNTHETIC") || strings.Contains(upper, "DO-NOT-USE") || strings.Contains(upper, "NOT-A-CREDENTIAL") || strings.Contains(upper, "EXAMPLE")
}

func isApprovedSeedURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" {
		return false
	}
	if parsed.Scheme != "https" {
		return false
	}
	if parsed.Hostname() != "example.invalid" {
		return false
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil {
		return false
	}
	return true
}

func isSyntheticPath(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	parts := strings.Split(strings.Trim(clean, "/"), "/")
	for index := 0; index+1 < len(parts); index++ {
		if parts[index] == "testdata" && (parts[index+1] == "fuzz" || parts[index+1] == "adversarial") {
			return true
		}
	}
	return false
}

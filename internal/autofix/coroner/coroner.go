// internal/autofix/coroner/coroner.go
package coroner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath" // <-- ADDED THIS IMPORT
	"regexp"
	"strconv"
	"strings"
)

// IncidentReport holds the structured data parsed from a panic log.
type IncidentReport struct {
	// The primary panic message (the argument passed to panic()).
	Message string
	// The full raw stack trace.
	StackTrace string
	// The most relevant file path where the panic originated (in application code).
	// This path is absolute as derived from the stack trace.
	FilePath string
	// The line number in the FilePath.
	LineNumber int
	// The name of the function where the panic occurred.
	FunctionName string
}

// Regex definitions for parsing standard Go panic output.
var (
	// Matches the start of the panic message.
	panicMessageRegex = regexp.MustCompile(`^panic: (.*)`)
	// Matches the function signature line in the stack trace.
	functionRegex = regexp.MustCompile(`^([a-zA-Z0-9_\-./\(\)\*]+)\(.*\)$`)
	// Matches the file path and line number line.
	locationRegex = regexp.MustCompile(`^\s+(.*\.go):(\d+)(?: .*)?$`)
)

// Parser is responsible for reading and interpreting panic logs.
type Parser struct{}

// NewParser creates a new Coroner parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseFile reads a panic log file and extracts structured information.
func (p *Parser) ParseFile(logPath string) (*IncidentReport, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open panic log file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read panic log file: %w", err)
	}

	return p.Parse(lines)
}

// Parse interprets the lines of a panic log.
func (p *Parser) Parse(lines []string) (*IncidentReport, error) {
	if len(lines) == 0 {
		return nil, fmt.Errorf("panic log is empty")
	}

	report := &IncidentReport{
		StackTrace: strings.Join(lines, "\n"),
	}

	// 1. Extract the panic message
	if matches := panicMessageRegex.FindStringSubmatch(lines[0]); len(matches) > 1 {
		report.Message = matches[1]
	} else {
		report.Message = lines[0]
	}

	// 2. Find the crash location
	foundLocation := false
	for i := 1; i < len(lines); i++ {
		line := lines[i]

		if strings.HasPrefix(line, "goroutine ") {
			continue
		}

		// Check if this line is a function signature
		if matches := functionRegex.FindStringSubmatch(line); len(matches) > 1 {
			funcName := matches[1]

			// Check the next line for the corresponding location
			if i+1 < len(lines) {
				locationLine := lines[i+1]
				if locMatches := locationRegex.FindStringSubmatch(locationLine); len(locMatches) == 3 {
					filePath := locMatches[1]
					lineNumberStr := locMatches[2]

					// Heuristic: Filter out Go runtime and standard library.
					// A better heuristic is to check if the directory path contains a dot,
					// as module paths (e.g., github.com) do, while standard library
					// paths (e.g., net/http, runtime) do not.
					packagePath := filepath.Dir(filePath)
					isStdLibOrRuntime := strings.Contains(filePath, "go/src/") && !strings.Contains(packagePath, ".")

					if isStdLibOrRuntime || strings.HasPrefix(funcName, "runtime.") {
						continue
					}

					// Filter out the Sentinel's recovery function itself (main.main.func1).
					if strings.HasPrefix(funcName, "main.main.func1") && strings.Contains(filePath, "cmd/scalpel/main.go") {
						continue
					}

					lineNumber, _ := strconv.Atoi(lineNumberStr)
					report.FilePath = filePath
					report.LineNumber = lineNumber
					report.FunctionName = funcName
					foundLocation = true
					break
				}
			}
		}
	}

	if !foundLocation {
		return nil, fmt.Errorf("could not reliably determine panic location in application code from stack trace")
	}

	return report, nil
}

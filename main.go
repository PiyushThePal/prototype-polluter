package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
	colorReset = "\033[0m"

	pollutionParam = "__proto__[testparam]=testval"
	detectorJS     = "window.testparam == 'testval'? 'Vulnerable' : 'Not Vulnerable'"
)

func ensurePageFetch() error {
	if _, err := exec.LookPath("page-fetch"); err == nil {
		return nil
	}
	fmt.Println("page-fetch not found in PATH, attempting `go install github.com/detectify/page-fetch@latest`...")
	cmd := exec.Command("go", "install", "github.com/detectify/page-fetch@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install page-fetch: %w", err)
	}
	if _, err := exec.LookPath("page-fetch"); err != nil {
		return fmt.Errorf("page-fetch still not in PATH after install — check that $GOPATH/bin (or $HOME/go/bin) is in PATH")
	}
	return nil
}

func buildTestURL(line string) string {
	if strings.Contains(line, "?") {
		return line + "&" + pollutionParam
	}
	return line + "?" + pollutionParam
}

func testURL(testURL string) (vulnerable bool, raw string, err error) {
	cmd := exec.Command("page-fetch", "-j", detectorJS, "-o", "/tmp/page-fetch-out")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, "", err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, "", err
	}
	if err := cmd.Start(); err != nil {
		return false, "", err
	}
	if _, err := io.WriteString(stdin, testURL+"\n"); err != nil {
		return false, "", err
	}
	stdin.Close()
	out, err := io.ReadAll(stdout)
	if err != nil {
		return false, "", err
	}
	if err := cmd.Wait(); err != nil {
		return false, string(out), err
	}
	output := string(out)
	for _, l := range strings.Split(output, "\n") {
		if strings.HasPrefix(l, "JS") && strings.Contains(l, "Vulnerable") {
			return !strings.Contains(l, "Not Vulnerable"), l, nil
		}
	}
	return false, output, nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-v] < urls.txt\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Reads URLs from stdin and tests each for client-side prototype pollution")
		fmt.Fprintln(os.Stderr, "by appending __proto__[testparam]=testval and checking if the rendered page")
		fmt.Fprintln(os.Stderr, "exposes window.testparam == 'testval'.")
		fmt.Fprintln(os.Stderr)
		flag.PrintDefaults()
	}
	verbose := flag.Bool("v", false, "Verbose mode — also print Not Vulnerable results")
	flag.Parse()

	if err := ensurePageFetch(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Starting.....")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		probe := buildTestURL(line)
		vuln, _, err := testURL(probe)
		if err != nil {
			if *verbose {
				fmt.Fprintf(os.Stderr, "%sError testing %s: %v%s\n", colorRed, probe, err, colorReset)
			}
			continue
		}
		if vuln {
			fmt.Printf("%sVulnerable --> %s%s\n", colorRed, probe, colorReset)
		} else if *verbose {
			fmt.Printf("%sNot Vulnerable --> %s%s\n", colorGreen, probe, colorReset)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

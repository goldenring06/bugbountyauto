package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	fileExtensions = regexp.MustCompile(`(?i)\.(php|aspx|jsp|json|conf|xml|env|gz|log|bak|old|zip|rar|7z|tar|sql|db|ini|config|yml|yaml|backup|passwd|htpasswd)(\?|$)`)

	// Color codes
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Reset  = "\033[0m"
)

func runCommandSilent(cmd *exec.Cmd) error {
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func writeToFile(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, line := range lines {
		file.WriteString(line + "\n")
	}
	return nil
}

func removeDuplicates(lines []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, line := range lines {
		if !seen[line] {
			seen[line] = true
			result = append(result, line)
		}
	}
	return result
}

func fetchWaybackURLs(domain string) []string {
	waybackURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", domain)

	tr := &http.Transport{
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableKeepAlives:     true,
	}
	client := &http.Client{
		Timeout:   40 * time.Second,
		Transport: tr,
	}

	var resp *http.Response
	var err error

	maxAttempts := 3
	for i := 1; i <= maxAttempts; i++ {
		resp, err = client.Get(waybackURL)
		if err == nil {
			break
		}
		log.Printf(Red+"[!] Wayback attempt %d failed: %v. Retrying in 3s..."+Reset, i, err)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Printf(Red+"[!] Failed to fetch wayback URLs after %d attempts: %v"+Reset, maxAttempts, err)
		return nil
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	var filtered []string
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if fileExtensions.MatchString(url) {
			filtered = append(filtered, url)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf(Red+"[!] Scanner error: %v"+Reset, err)
	}

	return filtered
}

func fetchWaybackSensitive(domain string, outputFile string) ([]string, error) {
	filter := `.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$`
	api := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original&filter=original:%s", domain, filter)

	resp, err := http.Get(api)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return nil, err
	}
	defer outFile.Close()

	var matches []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		url := scanner.Text()
		if url != "" {
			matches = append(matches, url)
			outFile.WriteString(url + "\n")
		}
	}
	return matches, scanner.Err()
}

var pdfSensitiveRegex = regexp.MustCompile(`(?i)(internal use only|confidential|strictly private|personal & confidential|private|restricted|internal|not for distribution|do not share|proprietary|trade secret|classified|sensitive|bank statement|invoice|salary|contract|agreement|non disclosure|passport|social security|ssn|date of birth|credit card|identity|id number|company confidential|staff only|management only|internal only)`)

func scanPDFforSecrets(url string) bool {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`curl -s "%s" | pdftotext - - | grep -Eaiq '%s'`, url, pdfSensitiveRegex.String()))
	err := cmd.Run()
	return err == nil
}


func main() {
	fmt.Println(Blue + "========== RECON TOOL START ==========" + Reset)
	fmt.Print(Blue + "[?] Enter domain: " + Reset)
	var domain string
	fmt.Scanln(&domain)

	outputDir := filepath.Join("output", domain)
	os.MkdirAll(outputDir, os.ModePerm)

	fmt.Println(Yellow + "[+] Finding subdomains using assetfinder and subfinder..." + Reset)
	subdomainFile := filepath.Join(outputDir, "subdomains.txt")
	subdomainCmd := exec.Command("bash", "-c", fmt.Sprintf("assetfinder --subs-only %s; subfinder -silent -d %s", domain, domain))
	output, _ := subdomainCmd.Output()
	subdomains := strings.Split(strings.TrimSpace(string(output)), "\n")
	subdomains = removeDuplicates(subdomains)
	writeToFile(subdomainFile, subdomains)
	fmt.Println(Green + "[✔] Subdomains written to: " + subdomainFile + Reset)

	fmt.Println(Yellow + "[+] Checking alive subdomains on common ports..." + Reset)
	aliveFile := filepath.Join(outputDir, "subdomains_alive.txt")
	httpxCmd := exec.Command("httpx-toolkit", "-ports", "80,443,8080,8000,8888", "-threads", "200", "-no-color")
	httpxCmd.Stdin = strings.NewReader(strings.Join(subdomains, "\n"))
	httpxOut, err := httpxCmd.Output()
	if err != nil {
		log.Fatalf(Red+"[!] Error running httpx-toolkit: %v"+Reset, err)
	}
	alive := strings.Split(strings.TrimSpace(string(httpxOut)), "\n")
	writeToFile(aliveFile, alive)
	fmt.Println(Green + "[✔] Alive subdomains written to: " + aliveFile + Reset)

	fmt.Println(Yellow + "[+] Running katana..." + Reset)
	katanaFile := filepath.Join(outputDir, "allurls.txt")
	katanaCmd := exec.Command("katana", "-silent", "-list", aliveFile, "-d", "5", "-kf", "-jc", "-fx", "-ef", "woff,woff2,css,svg,png,jpg,jpeg,gif,ico,ttf,eot")
	katanaOut, _ := katanaCmd.Output()
	katanaLines := strings.Split(strings.TrimSpace(string(katanaOut)), "\n")
	writeToFile(katanaFile, katanaLines)
	fmt.Println(Green + "[✔] Katana URLs written to: " + katanaFile + Reset)

	fmt.Println(Yellow + "[+] Running gau..." + Reset)
	gauFile := filepath.Join(outputDir, "gau_passive_urls.txt")
	gauCmd := exec.Command("gau", "--threads", "30")
	gauCmd.Stdin = strings.NewReader(strings.Join(subdomains, "\n"))
	gauOut, _ := gauCmd.Output()
	gauLines := strings.Split(strings.TrimSpace(string(gauOut)), "\n")
	writeToFile(gauFile, gauLines)
	fmt.Println(Green + "[✔] Gau URLs written to: " + gauFile + Reset)

	fmt.Println(Yellow + "[+] Fetching Wayback URLs..." + Reset)
	waybackURLs := fetchWaybackURLs(domain)
	allSensitiveFile := filepath.Join(outputDir, "all_sensitive_urls.txt")
	combined := append(katanaLines, gauLines...)
	combined = append(combined, waybackURLs...)
	combined = removeDuplicates(combined)
	sort.Strings(combined)

	var sensitive []string
	for _, url := range combined {
		if fileExtensions.MatchString(url) {
			sensitive = append(sensitive, url)
		}
	}
	writeToFile(allSensitiveFile, sensitive)
	fmt.Println(Green + "[✔] All sensitive URLs written to: " + allSensitiveFile + Reset)

	fmt.Println(Yellow + "[+] Merging allurls.txt and gau_passive_urls.txt..." + Reset)
	allURLs := make(map[string]struct{})

	if data, err := os.ReadFile(katanaFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				allURLs[line] = struct{}{}
			}
		}
	}
	if data, err := os.ReadFile(gauFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				allURLs[line] = struct{}{}
			}
		}
	}
	var merged []string
	for u := range allURLs {
		merged = append(merged, u)
	}
	sort.Strings(merged)
	mergedPath := filepath.Join(outputDir, "merged_allurls.txt")
	writeToFile(mergedPath, merged)
	fmt.Println(Green + "[✔] Merged URLs saved to: " + mergedPath + Reset)

	// Additional processing
	fmt.Println(Yellow + "[+] Extracting potential sensitive files from merged_allurls.txt..." + Reset)
	sensitiveRegex := regexp.MustCompile(`(?i)\.(txt|log|cache|secret|db|backup|yml|json|gz|rar|zip|config)(\?|$)`)
	var sensitiveHits []string
	for _, line := range merged {
		if sensitiveRegex.MatchString(line) {
			sensitiveHits = append(sensitiveHits, line)
		}
	}
	sensitiveOutFile := filepath.Join(outputDir, "potential_sensitive_files.txt")
	writeToFile(sensitiveOutFile, sensitiveHits)
	fmt.Println(Green + "[✔] Sensitive file patterns saved to: " + sensitiveOutFile + Reset)

	fmt.Println(Yellow + "[+] Extracting JS file URLs from merged_allurls.txt..." + Reset)
	var jsFiles []string
	for _, line := range merged {
		if strings.HasSuffix(line, ".js") {
			jsFiles = append(jsFiles, line)
		}
	}
	jsOutFile := filepath.Join(outputDir, "js.txt")
	writeToFile(jsOutFile, jsFiles)
	fmt.Println(Green + "[✔] JavaScript file URLs saved to: " + jsOutFile + Reset)

	/*fmt.Println(Yellow + "[+] Running nuclei on js.txt using exposures template..." + Reset)
	nucleiCmd := exec.Command("nuclei", "-t", "/home/kali/nuclei-templates/http/exposures", "-c", "30", "-silent")
	nucleiCmd.Stdin = strings.NewReader(strings.Join(jsFiles, "\n"))
	nucleiOut, err := nucleiCmd.Output()
	if err != nil {
		log.Printf(Red+"[!] Nuclei execution error: %v"+Reset, err)
	} else {
		fmt.Println(Green + "[✔] Nuclei scan on JS files complete!" + Reset)
		fmt.Println(string(nucleiOut)) // Optional: print results
	}*/

		// === Additional Final Tests ===

	fmt.Println(Yellow + "[+] Running subzy on alive subdomains..." + Reset)
	subzyCmd := exec.Command("bash", "-c", fmt.Sprintf("subzy run --targets %s --verify_ssl", aliveFile))
	subzyOut, err := subzyCmd.CombinedOutput()
	if err != nil {
		log.Printf(Red+"[!] subzy execution failed: %v"+Reset, err)
	} else {
		subzyResult := filepath.Join(outputDir, "subzy_output.txt")
		os.WriteFile(subzyResult, subzyOut, 0644)
		fmt.Println(Green + "[✔] Subzy results saved to: " + subzyResult + Reset)
	}

	fmt.Println(Yellow + "[+] Running Corsy on alive subdomains..." + Reset)
	corsyCmd := exec.Command("python3", "/home/kali/Corsy/corsy.py", "-i", aliveFile, "-t", "10", "--headers", "User-Agent: GoogleBot\nCookie: SESSION=Hacked")
	corsyOut, err := corsyCmd.CombinedOutput()
	if err != nil {
		log.Printf(Red+"[!] Corsy execution failed: %v"+Reset, err)
	} else {
		corsyResult := filepath.Join(outputDir, "corsy_output.txt")
		os.WriteFile(corsyResult, corsyOut, 0644)
		fmt.Println(Green + "[✔] Corsy results saved to: " + corsyResult + Reset)
	}

	
	// Optional: Run nuclei-based CORS scan instead of Corsy
	fmt.Println(Yellow + "[+] Running nuclei CORS scan..." + Reset)
	corsNucleiCmd := exec.Command("nuclei", "-list", aliveFile, "-t", "/home/kali/mangaldeep-templates/cors.yaml", "-c", "30", "-silent")
	corsOut, err := corsNucleiCmd.CombinedOutput()
	if err != nil {
		log.Printf(Red+"[!] Nuclei CORS scan failed: %v"+Reset, err)
	} else {
		corsNucleiResult := filepath.Join(outputDir, "cors_nuclei_output.txt")
		os.WriteFile(corsNucleiResult, corsOut, 0644)
		fmt.Println(Green + "[✔] Nuclei CORS scan results saved to: " + corsNucleiResult + Reset)
	}
	


		// === Wayback Sensitive File Fetch + PDF Secret Detection ===
	fmt.Println(Yellow + "[+] Fetching filtered sensitive URLs from Wayback..." + Reset)
	waybackSensitiveFile := filepath.Join(outputDir, "wayback_sensitive_urls.txt")
	waybackSensitive, err := fetchWaybackSensitive(domain, waybackSensitiveFile)
	if err != nil {
		log.Printf(Red+"[!] Error fetching filtered Wayback URLs: %v"+Reset, err)
	} else {
		fmt.Printf(Green+"[✔] %d filtered sensitive URLs saved to: %s\n"+Reset, len(waybackSensitive), waybackSensitiveFile)
	}

	fmt.Println(Yellow + "[+] Scanning Wayback PDFs for sensitive content..." + Reset)
	var sensitivePDFs []string
	for _, url := range waybackSensitive {
		if strings.HasSuffix(strings.ToLower(url), ".pdf") {
			if scanPDFforSecrets(url) {
				fmt.Println(Red + "[!] Sensitive PDF found: " + url + Reset)
				sensitivePDFs = append(sensitivePDFs, url)
			}
		}
	}
	if len(sensitivePDFs) > 0 {
		pdfOutput := filepath.Join(outputDir, "sensitive_pdfs.txt")
		writeToFile(pdfOutput, sensitivePDFs)
		fmt.Println(Green + "[✔] Sensitive PDF URLs saved to: " + pdfOutput + Reset)
	}



	fmt.Println(Blue + "========== RECON COMPLETE ==========" + Reset)
	fmt.Println(Green + "[✔] Domain: " + domain + " — Results stored in: " + outputDir + Reset)
}

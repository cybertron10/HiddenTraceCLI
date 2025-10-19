package main



import (

	"bufio"

	"context"

	"flag"

	"fmt"

	"io"
	"log"

	"net/http"
	"net/url"

	"os"
	"os/exec"

	"path/filepath"

	"strings"

	"sync"

	"time"



	"github.com/cybertron10/HiddenTraceCLI/internal/crawler/crawler"

	"github.com/cybertron10/HiddenTraceCLI/internal/paramsmapper"

	"github.com/cybertron10/HiddenTraceCLI/internal/scanner"

)



// sendNotification sends a notification using the notify command
func sendNotification(message string) {
	if message == "" {
		return
	}
	
	// Run in background to avoid blocking
	go func() {
		// Use echo to pipe the message to notify
		cmd := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' | notify", message))
		
		if err := cmd.Run(); err != nil {
			// Silently fail if notify command is not available
			// This prevents errors when notify is not installed
		}
	}()
}

func main() {

	var (

		targetURL   = flag.String("url", "", "Target URL or domain to scan")

		urlFile     = flag.String("file", "", "File containing list of URLs to scan (one per line)")

		concurrency = flag.Int("concurrency", 20, "Concurrent scans (increased default for better performance)")

		headless    = flag.Bool("headless", true, "Use headless browser")

		fast       = flag.Bool("fast-mode", true, "Fast mode payload set (default: true for better performance)")

		ultra      = flag.Bool("ultra-fast", false, "Ultra fast mode")

		outputDir   = flag.String("output", "scan_results", "Output file (.txt) or directory for results")

		wordlist    = flag.String("wordlist", "wordlist.txt", "Path to parameter wordlist file")

		quiet       = flag.Bool("quiet", false, "Quiet output (only key progress and findings)")
		maxParams   = flag.Int("max-params", 0, "Maximum number of parameters to test (0 = all)")
		maxURLs     = flag.Int("max-urls", 200, "Maximum URLs per domain before skipping parameter fuzzing")
		maxValidParams = flag.Int("max-valid-params", 10, "Maximum valid parameters per URL before considering it a false positive")
		notify      = flag.Bool("notify", false, "Send real-time notifications for XSS vulnerabilities found")
	)

	flag.Parse()



	if *targetURL == "" && *urlFile == "" {

		fmt.Println("Usage: hiddentrace-cli -url https://example.com [options]")

		fmt.Println("   or: hiddentrace-cli -file urls.txt [options]")

		flag.PrintDefaults()

		return

	}



	if *targetURL != "" && *urlFile != "" {

		fmt.Println("Error: Cannot specify both -url and -file. Use one or the other.")

		return

	}



	// Determine if output is a file or directory

	var outputFile string

	
	
	if strings.HasSuffix(*outputDir, ".txt") {

		// Output is a file path

		outputFile = *outputDir

		// Create parent directory if it doesn't exist

		parentDir := filepath.Dir(outputFile)

		if err := os.MkdirAll(parentDir, 0755); err != nil {

			log.Fatalf("Failed to create output directory: %v", err)

		}

	} else {

		// Output is a directory

		if err := os.MkdirAll(*outputDir, 0755); err != nil {

			log.Fatalf("Failed to create output directory: %v", err)

		}

		outputFile = filepath.Join(*outputDir, "xss_vulnerabilities.txt")

	}



	// Determine target URLs

	var targetURLs []string

	var scanTarget string

	
	
	if *urlFile != "" {

		// Load URLs from file

		log.Printf("Loading URLs from file: %s", *urlFile)

		urls, err := loadURLsFromFile(*urlFile)

		if err != nil {

			log.Fatalf("Failed to load URLs from file: %v", err)

		}

		targetURLs = urls

		scanTarget = fmt.Sprintf("file: %s (%d URLs)", *urlFile, len(urls))

		log.Printf("Loaded %d URLs from file", len(urls))

	} else {

		// Single URL

		targetURLs = []string{*targetURL}

		scanTarget = *targetURL

	}
	
	

	if !*quiet { log.Printf("Starting HiddenTrace CLI scan for: %s", scanTarget) }


	// 1) Crawl

	// Process each domain completely (all phases) before moving to next
	var allVulnerabilities []scanner.Vulnerability
	var allHiddenURLs []string
	var allParams []string
	
	for i, targetURL := range targetURLs {
		log.Printf("=== Processing domain %d/%d: %s ===", i+1, len(targetURLs), targetURL)
		
		// 1) Web Crawling for this domain
		if !*quiet { log.Printf("Phase 1: Web crawling %s...", targetURL) }
		
		c := crawler.NewCrawler(*quiet)
		crawl, err := c.CrawlDomain(targetURL, map[string]string{})
		
		if err != nil {
			if !*quiet { log.Printf("Warning: Failed to crawl %s: %v", targetURL, err) }
			continue
		}
		
		if !*quiet { log.Printf("Crawl complete for %s: %d URLs discovered", targetURL, len(crawl.URLs)) }
		
		// Check if this domain has too many URLs and skip parameter fuzzing
		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			continue
		}
		domain := parsedURL.Host
		
		// Count URLs for this domain
		domainURLCount := 0
		for _, crawledURL := range crawl.URLs {
			crawledParsed, err := url.Parse(crawledURL)
			if err != nil {
				continue
			}
			if crawledParsed.Host == domain {
				domainURLCount++
			}
		}
		
		var skipParameterFuzzing bool
		if domainURLCount > *maxURLs {
			skipParameterFuzzing = true
			if !*quiet { log.Printf("Skipping parameter fuzzing for domain %s: %d URLs exceeds limit of %d", domain, domainURLCount, *maxURLs) }
		}

		// 2) Parameter extraction for this domain
		if !*quiet { log.Printf("Phase 2: Parameter extraction for %s...", targetURL) }
		var domainParams []string
		for _, params := range crawl.Parameters {
			for _, param := range params {
				domainParams = append(domainParams, param.Name)
			}
		}
		allParams = append(allParams, domainParams...)
		if !*quiet { log.Printf("Extracted %d parameters from %s", len(domainParams), targetURL) }
		
		// 3) Parameter fuzzing for this domain (if not skipped)
		var domainHiddenURLs []string
		if !skipParameterFuzzing {
			if !*quiet { log.Printf("Phase 3: Parameter fuzzing for %s...", targetURL) }
			domainHiddenURLs = processParameterFuzzing(crawl.URLs, targetURL, i+1, len(targetURLs), *wordlist, *maxParams, *maxValidParams, *quiet)
		} else {
			if !*quiet { log.Printf("Phase 3: Skipping parameter fuzzing for %s (too many URLs)", targetURL) }
		}
		allHiddenURLs = append(allHiddenURLs, domainHiddenURLs...)
		
		// 4) Reflection filtering for this domain
		if !*quiet { log.Printf("Phase 4: Reflection filtering for %s...", targetURL) }
		allURLs := append(crawl.URLs, domainHiddenURLs...)
		reflectingURLs := filterReflectingURLs(allURLs, *quiet)
		if !*quiet { log.Printf("Reflection filtering complete for %s: %d/%d URLs have reflecting parameters", targetURL, len(reflectingURLs), len(allURLs)) }
		
		// 5) XSS scanning for this domain
		if len(reflectingURLs) == 0 {
			if !*quiet { log.Printf("No URLs with reflecting parameters found for %s. Skipping XSS scanning.", targetURL) }
		} else {
			if !*quiet { log.Printf("Phase 5: XSS scanning for %s...", targetURL) }
			domainVulns := processXSSScanning(reflectingURLs, targetURL, *concurrency, *headless, *fast, *ultra, *notify, *quiet)
			allVulnerabilities = append(allVulnerabilities, domainVulns...)
		}
		
		log.Printf("=== Completed domain %d/%d: %s ===", i+1, len(targetURLs), targetURL)
	}


	// Save XSS vulnerabilities to output file
	if len(allVulnerabilities) > 0 {
		if err := saveVulnerabilitiesToFile(outputFile, allVulnerabilities); err != nil {
			log.Printf("Error saving vulnerabilities to file: %v", err)
		} else {
			if !*quiet { log.Printf("XSS vulnerabilities saved to: %s", outputFile) }
		}
	} else {
		if !*quiet { log.Printf("No XSS vulnerabilities found") }
	}

	// Final summary
	if !*quiet { log.Printf("Scan complete! XSS vulnerabilities saved to: %s", outputFile) }
	if !*quiet { log.Printf("Summary: %d domains processed, %d parameters found, %d hidden URLs discovered, %d XSS vulnerabilities found", 
		len(targetURLs), len(allParams), len(allHiddenURLs), len(allVulnerabilities)) }

	// Scan completed



}

// Helper functions for domain processing

func processParameterFuzzing(urls []string, targetURL string, currentDomain, totalDomains int, wordlist string, maxParams int, maxValidParams int, quiet bool) []string {
	// Load wordlist
	wordlistParams := paramsmapper.LoadWordlist(wordlist)
	if maxParams > 0 && len(wordlistParams) > maxParams {
		wordlistParams = wordlistParams[:maxParams]
		if !quiet { log.Printf("Limited to first %d parameters from wordlist", maxParams) }
	}
	if !quiet { log.Printf("Loaded %d parameters from wordlist", len(wordlistParams)) }
	paramsmapper.SetQuiet(quiet)
	
	var hiddenURLs []string
	var allResults []paramsmapper.Results

	for i, urlStr := range urls {
		if !quiet { log.Printf("Processing URL %d/%d: %s", i+1, len(urls), urlStr) }
		
		request := paramsmapper.Request{
			URL:     urlStr,
			Method:  "GET",
			Timeout: 3, // Reduced from 5s to 3s
		}
		
		// Add timeout context for parameter fuzzing
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute) // Further reduced to 1min
		defer cancel()
		
		// Use a channel to handle timeout
		resultsChan := make(chan paramsmapper.Results, 1)
		
		go func() {
			// Create a context that can be cancelled for early termination
			paramCtx, paramCancel := context.WithCancel(ctx)
			defer paramCancel()
			
			// Channel to signal early termination
			earlyTermChan := make(chan bool, 1)
			
			// Start parameter discovery in a separate goroutine
			var results paramsmapper.Results
			done := make(chan bool, 1)
			
			go func() {
				results = paramsmapper.DiscoverParamsWithProgressAndContext(paramCtx, request, wordlistParams, 100, func(progress paramsmapper.ProgressInfo) bool { // Reduced chunk size from 200 to 100
					if !quiet {
						// Log progress more frequently to track activity
						if progress.Percentage%10 == 0 || progress.Stage == "discovery" {
							log.Printf("URL %d/%d - %s (discovered: %d)", i+1, len(urls), progress.Message, progress.Discovered)
						}
					}
					
					// Early termination if too many parameters discovered (likely false positive)
					if progress.Discovered > maxValidParams {
						if !quiet { log.Printf("URL %d/%d - Too many parameters discovered (%d), stopping fuzzing (likely false positive)", i+1, len(urls), progress.Discovered) }
						
						// Signal early termination
						select {
						case earlyTermChan <- true:
						default:
						}
						
						return false // Return false to abort
					}
					
					// Additional early termination for slow progress
					if progress.Stage == "discovery" && progress.Discovered > 0 && progress.Percentage > 50 {
						// If we're 50% through and only found a few parameters, likely not worth continuing
						if progress.Discovered < 3 {
							if !quiet { log.Printf("URL %d/%d - Slow progress, stopping early (found %d params at %d%%)", i+1, len(urls), progress.Discovered, progress.Percentage) }
							return false
						}
					}
					
					return true // Continue processing
				})
				done <- true
			}()
			
			// Wait for either completion or early termination
			select {
			case <-done:
				// Normal completion
			case <-earlyTermChan:
				// Early termination requested - cancel context and wait a bit for cleanup
				paramCancel()
				time.Sleep(100 * time.Millisecond) // Give it time to cleanup
				
				// Return empty results for early termination
				results = paramsmapper.Results{
					Params:        []string{},
					FormParams:    []string{},
					Aborted:       true,
					AbortReason:   fmt.Sprintf("Too many parameters discovered (false positive) - stopped at %d", maxValidParams),
					TotalRequests: 0,
					Request:       request,
				}
			case <-ctx.Done():
				// Timeout occurred
				paramCancel()
				results = paramsmapper.Results{
					Params:        []string{},
					FormParams:    []string{},
					Aborted:       true,
					AbortReason:   "Timeout after 5 minutes",
					TotalRequests: 0,
					Request:       request,
				}
			}
			
			resultsChan <- results
		}()
		
		var results paramsmapper.Results
		select {
		case results = <-resultsChan:
			// Parameter fuzzing completed successfully or was stopped early
		case <-ctx.Done():
			// Timeout occurred
			if !quiet { log.Printf("URL %d/%d - Parameter fuzzing timeout after 5 minutes, skipping", i+1, len(urls)) }
			results = paramsmapper.Results{
				Params:        []string{},
				FormParams:    []string{},
				Aborted:       true,
				AbortReason:   "Timeout after 5 minutes",
				TotalRequests: 0,
				Request:       request,
			}
		}
		
		// Store results with URL context
		allResults = append(allResults, results)
	}

	// Generate hidden URLs from discovered parameters
	for _, result := range allResults {
		if result.Aborted {
			if !quiet { log.Printf("Skipping URL due to fuzzing issues: %s - %s", result.Request.URL, result.AbortReason) }
			continue
		}
		
		// Combine discovered parameters with the original URL
		if len(result.Params) > 0 {
			parsedURL, err := url.Parse(result.Request.URL)
			if err != nil {
				continue
			}
			
			// Create URLs with discovered parameters
			query := parsedURL.Query()
			for _, param := range result.Params {
				query.Set(param, "test")
			}
			parsedURL.RawQuery = query.Encode()
			hiddenURLs = append(hiddenURLs, parsedURL.String())
		}
	}
	
	if !quiet { log.Printf("Parameter fuzzing complete for %s: %d hidden URLs generated", targetURL, len(hiddenURLs)) }
	return hiddenURLs
}

func processXSSScanning(urls []string, targetURL string, concurrency int, headless bool, fast bool, ultra bool, notify bool, quiet bool) []scanner.Vulnerability {
	var vulnerabilities []scanner.Vulnerability
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Process URLs in chunks to avoid overwhelming the system
	chunkSize := concurrency
	for i := 0; i < len(urls); i += chunkSize {
		end := i + chunkSize
		if end > len(urls) {
			end = len(urls)
		}
		
		chunk := urls[i:end]
		
		for _, urlStr := range chunk {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				
				// Create a new scanner instance for this URL
				urlConfig := &scanner.Config{
					URL:       url,
					Headers:   make(map[string]string),
					Quiet:     quiet,
					Headless:  headless,
					FastMode:  fast,
					UltraFast: ultra,
					Timeout:   10 * time.Second, // Reduced from 30s to 10s
				}
				
				scannerInstance := scanner.NewScanner(urlConfig)
				defer scannerInstance.Close()
				
				ctx := context.Background()
				result, err := scannerInstance.Scan(ctx)
				
				mu.Lock()
				if err == nil && result != nil {
					vulnerabilities = append(vulnerabilities, result.Vulnerabilities...)

					// Always show per-URL finding lines with exploit URLs and payloads
					for _, vuln := range result.Vulnerabilities {
						payloads := strings.Join(vuln.WorkingPayloads, ", ")
						log.Printf("Found XSS vulnerability in %s - Parameter: %s - Payload: %s", vuln.ExploitURL, vuln.Parameter, payloads)
						
						// Send notification if enabled
						if notify {
							notificationMsg := fmt.Sprintf("Found XSS vulnerability in %s - Parameter: %s - Payload: %s", vuln.ExploitURL, vuln.Parameter, payloads)
							sendNotification(notificationMsg)
						}
					}
				}
				mu.Unlock()

			}(urlStr)
		}
		
		wg.Wait()
		
		// Progress update
		if !quiet { log.Printf("XSS scan progress for %s: %d/%d URLs completed", targetURL, end, len(urls)) }
	}
	
	if !quiet { log.Printf("XSS scanning complete for %s: %d vulnerabilities found", targetURL, len(vulnerabilities)) }
	return vulnerabilities
}

// filterReflectingURLs tests all URLs for parameter reflection and returns only those with reflecting parameters
func filterReflectingURLs(urls []string, quiet bool) []string {
	if !quiet { log.Printf("Testing %d URLs for parameter reflection...", len(urls)) }

	var reflectingURLs []string
	client := &http.Client{Timeout: 3 * time.Second} // Further reduced timeout
	testValue := "surajishere"

	for i, urlStr := range urls {
		if !quiet && (i+1)%50 == 0 { // More frequent progress updates
			log.Printf("Reflection test progress: %d/%d URLs tested", i+1, len(urls))
		}

		parsedURL, err := url.Parse(urlStr)
	if err != nil {
			continue
		}

		// Get existing query parameters
		query := parsedURL.Query()
		if len(query) == 0 {
			// Skip URLs without parameters - they can't reflect parameters
			if !quiet { log.Printf("Skipping URL without parameters: %s", urlStr) }
			continue
		}

		// Test each parameter for reflection
		hasReflectingParam := false
		for paramName := range query {
			// Create test URL with the test value
			testURL := *parsedURL
			testQuery := testURL.Query()
			testQuery.Set(paramName, testValue)
			testURL.RawQuery = testQuery.Encode()

			// Make request with timeout
			resp, err := client.Get(testURL.String())
			if err != nil {
				if !quiet { log.Printf("Request failed for %s: %v", testURL.String(), err) }
				continue
			}

			// Read response body
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
	if err != nil {
				continue
			}

			// Check if test value reflects in response
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(testValue)) {
				hasReflectingParam = true
				if !quiet { log.Printf("Parameter %s reflects in %s", paramName, urlStr) }
				break // Found at least one reflecting parameter, no need to test others
			}
		}

		if hasReflectingParam {
			reflectingURLs = append(reflectingURLs, urlStr)
		} else {
			if !quiet { log.Printf("No reflecting parameters found in: %s", urlStr) }
		}
	}

	return reflectingURLs
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

func loadURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Validate URL format
			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				urls = append(urls, line)
			} else {
				log.Printf("Warning: Skipping invalid URL format: %s", line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// saveVulnerabilitiesToFile saves XSS vulnerabilities to a file
func saveVulnerabilitiesToFile(filename string, vulnerabilities []scanner.Vulnerability) error {
	if len(vulnerabilities) == 0 {
		return nil
	}

	var content strings.Builder
	content.WriteString("# XSS Vulnerabilities Found\n\n")
	
	for i, vuln := range vulnerabilities {
		content.WriteString(fmt.Sprintf("## Vulnerability %d\n", i+1))
		content.WriteString(fmt.Sprintf("URL: %s\n", vuln.ExploitURL))
		content.WriteString(fmt.Sprintf("Parameter: %s\n", vuln.Parameter))
		content.WriteString(fmt.Sprintf("Method: %s\n", vuln.Method))
		content.WriteString(fmt.Sprintf("Context: %s\n", vuln.Context))
		content.WriteString(fmt.Sprintf("Confidence: %s\n", vuln.Confidence))
		content.WriteString(fmt.Sprintf("Working Payloads: %s\n", strings.Join(vuln.WorkingPayloads, ", ")))
		content.WriteString(fmt.Sprintf("Directly Exploitable: %t\n", vuln.IsDirectlyExploitable))
		content.WriteString(fmt.Sprintf("Manual Intervention Required: %t\n", vuln.ManualInterventionRequired))
		content.WriteString("\n")
	}

	return os.WriteFile(filename, []byte(content.String()), 0644)
}

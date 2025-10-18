package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cybertron10/HiddenTraceCLI/internal/crawler/crawler"
	"github.com/cybertron10/HiddenTraceCLI/internal/enhancedParamExtractor"
	"github.com/cybertron10/HiddenTraceCLI/internal/paramsmapper"
	"github.com/cybertron10/HiddenTraceCLI/internal/scanner"
)

func main() {
	var (
		targetURL   = flag.String("url", "", "Target URL or domain to scan")
		urlFile     = flag.String("file", "", "File containing list of URLs to scan (one per line)")
		concurrency = flag.Int("concurrency", 10, "Concurrent scans")
		headless    = flag.Bool("headless", true, "Use headless browser")
		fast       = flag.Bool("fast-mode", false, "Fast mode payload set")
		ultra      = flag.Bool("ultra-fast", false, "Ultra fast mode")
		timeout     = flag.Duration("timeout", 10*time.Minute, "Scan timeout")
		outputDir   = flag.String("output", "scan_results", "Output file (.txt) or directory for results")
		wordlist    = flag.String("wordlist", "wordlist.txt", "Path to parameter wordlist file")
		quiet       = flag.Bool("quiet", false, "Quiet output (only key progress and findings)")
		maxParams   = flag.Int("max-params", 0, "Maximum number of parameters to test (0 = all)")
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
	if !*quiet { log.Println("Phase 1: Web crawling...") }
	
	// Crawl each target URL and combine results
	var allCrawledURLs []string
	var allParameters map[string][]crawler.Parameter = make(map[string][]crawler.Parameter)
	var allEndpoints []string
	totalPages := 0
	var totalScanTime time.Duration
	
	for i, targetURL := range targetURLs {
		// Always show per-target crawl start line
		log.Printf("Crawling target %d/%d: %s", i+1, len(targetURLs), targetURL)
		// Create a new crawler instance for each URL to avoid channel conflicts
		c := crawler.NewCrawler(*quiet)
		crawl, err := c.CrawlDomain(targetURL, map[string]string{})
		if err != nil {
			if !*quiet { log.Printf("Warning: Failed to crawl %s: %v", targetURL, err) }
			continue
		}
		
		// Combine results
		allCrawledURLs = append(allCrawledURLs, crawl.URLs...)
		for url, params := range crawl.Parameters {
			allParameters[url] = params
		}
		allEndpoints = append(allEndpoints, crawl.Endpoints...)
		totalPages += crawl.TotalPages
		totalScanTime += crawl.ScanTime
	}
	
	// Create combined crawl result
	crawl := &crawler.CrawlResult{
		URLs:       allCrawledURLs,
		Parameters: allParameters,
		Endpoints:  allEndpoints,
		TotalPages: totalPages,
		ScanTime:   totalScanTime,
	}
	
	if !*quiet { log.Printf("Crawl complete: %d URLs discovered across %d targets", len(crawl.URLs), len(targetURLs)) }

	// Skip saving crawl results - only XSS vulnerabilities needed

	// 2) Parameter extraction
	if !*quiet { log.Println("Phase 2: Parameter extraction...") }
	allParams := enhancedParamExtractor.ExtractAllParameters(crawl)
	if !*quiet { log.Printf("Parameter extraction complete: %d parameters found", len(allParams)) }

	// Skip saving parameters - only XSS vulnerabilities needed

	// 3) Parameter fuzzing with wordlist
	if !*quiet { log.Println("Phase 3: Parameter fuzzing...") }
	hiddenURLs := []string{}
	allURLs := crawl.URLs

	// Load wordlist
	wordlistParams := paramsmapper.LoadWordlist(*wordlist)
	if *maxParams > 0 && len(wordlistParams) > *maxParams {
		wordlistParams = wordlistParams[:*maxParams]
		if !*quiet { log.Printf("Limited to first %d parameters from wordlist", *maxParams) }
	}
	if !*quiet { log.Printf("Loaded %d parameters from wordlist", len(wordlistParams)) }
	paramsmapper.SetQuiet(*quiet)

	// Process all URLs together (fuzz every endpoint for comprehensive coverage)
	var allResults []paramsmapper.Results

	if !*quiet { log.Printf("Fuzzing %d URLs for hidden parameters...", len(crawl.URLs)) }
	
	for i, targetURL := range crawl.URLs {
		if !*quiet { log.Printf("Processing URL %d/%d: %s", i+1, len(crawl.URLs), targetURL) }
		
		request := paramsmapper.Request{
			URL:     targetURL,
			Method:  "GET",
			Timeout: 5, // Reduced timeout for faster requests
		}
		
		// Add timeout context for parameter fuzzing
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		
		// Use a channel to handle timeout
		resultsChan := make(chan paramsmapper.Results, 1)
		go func() {
			results := paramsmapper.DiscoverParamsWithProgress(request, wordlistParams, 200, func(progress paramsmapper.ProgressInfo) {
				if !*quiet {
					// Log progress more frequently to track activity
					if progress.Percentage%10 == 0 || progress.Stage == "discovery" {
						log.Printf("URL %d/%d - %s (discovered: %d)", i+1, len(crawl.URLs), progress.Message, progress.Discovered)
					}
				}
			})
			resultsChan <- results
		}()
		
		var results paramsmapper.Results
		select {
		case results = <-resultsChan:
			// Parameter fuzzing completed successfully
		case <-ctx.Done():
			// Timeout occurred
			if !*quiet { log.Printf("URL %d/%d - Parameter fuzzing timeout after 5 minutes, skipping", i+1, len(crawl.URLs)) }
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

	// Count total parameters discovered
	totalParams := 0
	totalFormParams := 0
	totalRequests := 0
	
	for _, result := range allResults {
		totalParams += len(result.Params)
		totalFormParams += len(result.FormParams)
		totalRequests += result.TotalRequests
	}

	if !*quiet { log.Printf("Parameter fuzzing complete: %d parameters discovered across all URLs", totalParams) }

	// Generate hidden URLs - only apply parameters to the specific URLs where they were discovered
	for _, result := range allResults {
		// Only process if parameters were discovered for this URL
		if len(result.Params) > 0 {
			if !*quiet { log.Printf("Applying %d discovered parameters to URL: %s", len(result.Params), result.Request.URL) }
			for _, param := range result.Params {
				hiddenURL := generateURLWithParam(result.Request.URL, param)
				hiddenURLs = append(hiddenURLs, hiddenURL)
			}
		}
	}

	if !*quiet { log.Printf("Generated %d hidden URLs with discovered parameters", len(hiddenURLs)) }
	allURLs = append(allURLs, hiddenURLs...)

	// Check for and remove duplicates
	originalCount := len(allURLs)
	allURLs = removeDuplicates(allURLs)
	duplicateCount := originalCount - len(allURLs)
	
	if duplicateCount > 0 {
		if !*quiet { log.Printf("Found %d duplicate URLs, removed them. Final unique URLs: %d", duplicateCount, len(allURLs)) }
	} else {
		if !*quiet { log.Printf("No duplicate URLs found. Total unique URLs: %d", len(allURLs)) }
	}

	// Skip saving URLs - only XSS vulnerabilities needed

	// 4) Reflection Filtering
	if !*quiet { log.Println("Phase 4: Reflection filtering...") }
	reflectingURLs := filterReflectingURLs(allURLs, *quiet)
	if !*quiet { log.Printf("Reflection filtering complete: %d/%d URLs have reflecting parameters", len(reflectingURLs), len(allURLs)) }
	
	// If no URLs have reflecting parameters, skip XSS scanning entirely
	if len(reflectingURLs) == 0 {
		if !*quiet { log.Println("No URLs with reflecting parameters found. Skipping XSS scanning.") }
		fmt.Println("xss scan completed")
		return
	}

	// 5) XSS Scanning
	if !*quiet { log.Println("Phase 5: XSS scanning...") }
	scanCfg := &scanner.Config{
		Quiet:     *quiet,
		Headless:  *headless,
		FastMode:  *fast,
		UltraFast: *ultra,
		Timeout:   *timeout,
	}

	var vulnerabilities []scanner.Vulnerability
	sem := make(chan struct{}, *concurrency)
	done := make(chan struct{})
	count := 0
	completed := 0
	var mu sync.Mutex

	if !*quiet { log.Printf("Starting XSS scan of %d URLs with concurrency %d", len(reflectingURLs), *concurrency) }

	for i, u := range reflectingURLs {
		u := u
		urlIndex := i + 1
		sem <- struct{}{}
		count++
		go func() {
			defer func() { 
				<-sem
				mu.Lock()
				completed++
				if !*quiet { log.Printf("XSS scan progress: %d/%d URLs completed", completed, len(reflectingURLs)) }
				mu.Unlock()
				done <- struct{}{} 
			}()
			
			if !*quiet { log.Printf("Scanning URL %d/%d: %s", urlIndex, len(reflectingURLs), u) }
			cfg := *scanCfg
			cfg.URL = u
			s := scanner.NewScanner(&cfg)
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()
			result, err := s.Scan(ctx)
			if err != nil {
				if !*quiet { log.Printf("XSS scan error for %s: %v", u, err) }
				return
			}
			if result != nil && len(result.Vulnerabilities) > 0 {
				mu.Lock()
				vulnerabilities = append(vulnerabilities, result.Vulnerabilities...)
				// Always show per-URL finding lines with exploit URLs and payloads
				for _, vuln := range result.Vulnerabilities {
					payloads := strings.Join(vuln.WorkingPayloads, ", ")
					log.Printf("Found XSS vulnerability in %s - Parameter: %s - Payload: %s", vuln.ExploitURL, vuln.Parameter, payloads)
				}
				mu.Unlock()
			}
		}()
	}

	for i := 0; i < count; i++ {
		<-done
	}

	// Save XSS results
	if err := saveXSSResults(vulnerabilities, outputFile); err != nil {
		if !*quiet { log.Printf("Warning: Failed to save XSS results: %v", err) }
	}

	// Skip generating summary - only XSS vulnerabilities needed

	if !*quiet { log.Printf("Scan complete! XSS vulnerabilities saved to: %s", outputFile) }
	if !*quiet { log.Printf("Summary: %d URLs crawled, %d parameters found, %d hidden URLs discovered, %d XSS vulnerabilities found", 
		len(crawl.URLs), len(allParams), len(hiddenURLs), len(vulnerabilities)) }

	// Always print a final completion message
	fmt.Println("xss scan completed")
}

// filterReflectingURLs tests all URLs for parameter reflection and returns only those with reflecting parameters
func filterReflectingURLs(urls []string, quiet bool) []string {
	if !quiet { log.Printf("Testing %d URLs for parameter reflection...", len(urls)) }
	
	var reflectingURLs []string
	client := &http.Client{Timeout: 5 * time.Second} // Reduced timeout
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
			// No parameters to test, skip this URL
			if !quiet { log.Printf("Skipping URL with no parameters: %s", urlStr) }
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

// Helper functions
func saveCrawlResults(crawl *crawler.CrawlResult, filename string) error {
	data, err := json.MarshalIndent(crawl, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func saveParameters(params []string, filename string) error {
	content := strings.Join(params, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}

func saveURLs(urls []string, filename string) error {
	content := strings.Join(urls, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}

func saveXSSResults(vulns []scanner.Vulnerability, filename string) error {
	var lines []string
	for _, vuln := range vulns {
		payloads := strings.Join(vuln.WorkingPayloads, ", ")
		lines = append(lines, fmt.Sprintf("%s - %s - %s", vuln.ExploitURL, vuln.Parameter, payloads))
	}
	content := strings.Join(lines, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}

func generateURLWithParam(baseURL, param string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := u.Query()
	q.Set(param, "test")
	u.RawQuery = q.Encode()
	return u.String()
}

type ScanSummary struct {
	TargetURL           string        `json:"target_url"`
	ScanDuration        time.Duration `json:"scan_duration"`
	CrawledURLs         int           `json:"crawled_urls"`
	DiscoveredParams    int           `json:"discovered_parameters"`
	HiddenURLs          int           `json:"hidden_urls"`
	XSSVulnerabilities  int           `json:"xss_vulnerabilities"`
	TotalURLs           int           `json:"total_urls"`
	Timestamp           time.Time     `json:"timestamp"`
}

func generateSummary(crawl *crawler.CrawlResult, params []string, hiddenURLs []string, vulns []scanner.Vulnerability, duration time.Duration, scanTarget string) ScanSummary {
	return ScanSummary{
		TargetURL:          scanTarget,
		ScanDuration:       duration,
		CrawledURLs:        len(crawl.URLs),
		DiscoveredParams:   len(params),
		HiddenURLs:         len(hiddenURLs),
		XSSVulnerabilities: len(vulns),
		TotalURLs:          len(crawl.URLs) + len(hiddenURLs),
		Timestamp:          time.Now(),
	}
}

func saveSummary(summary ScanSummary, filename string) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
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

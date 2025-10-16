package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
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
	
	log.Printf("Starting HiddenTrace CLI scan for: %s", scanTarget)

	// 1) Crawl
	log.Println("Phase 1: Web crawling...")
	
	// Crawl each target URL and combine results
	var allCrawledURLs []string
	var allParameters map[string][]crawler.Parameter = make(map[string][]crawler.Parameter)
	var allEndpoints []string
	totalPages := 0
	var totalScanTime time.Duration
	
	for i, targetURL := range targetURLs {
		log.Printf("Crawling target %d/%d: %s", i+1, len(targetURLs), targetURL)
		// Create a new crawler instance for each URL to avoid channel conflicts
		c := crawler.NewCrawler()
		crawl, err := c.CrawlDomain(targetURL, map[string]string{})
		if err != nil {
			log.Printf("Warning: Failed to crawl %s: %v", targetURL, err)
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
	
	log.Printf("Crawl complete: %d URLs discovered across %d targets", len(crawl.URLs), len(targetURLs))

	// Skip saving crawl results - only XSS vulnerabilities needed

	// 2) Parameter extraction
	log.Println("Phase 2: Parameter extraction...")
	allParams := enhancedParamExtractor.ExtractAllParameters(crawl)
	log.Printf("Parameter extraction complete: %d parameters found", len(allParams))

	// Skip saving parameters - only XSS vulnerabilities needed

	// 3) Parameter fuzzing with wordlist
	log.Println("Phase 3: Parameter fuzzing...")
	hiddenURLs := []string{}
	allURLs := crawl.URLs

	// Load wordlist
	wordlistParams := paramsmapper.LoadWordlist(*wordlist)
	log.Printf("Loaded %d parameters from wordlist", len(wordlistParams))

	// Process each target domain (like the web app does) instead of each individual URL
	var allResults paramsmapper.Results
	allResults.Params = []string{}
	allResults.FormParams = []string{}
	allResults.TotalRequests = 0

	// Get unique base domains from target URLs
	baseDomains := make(map[string]bool)
	for _, targetURL := range targetURLs {
		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			continue
		}
		baseDomain := parsedURL.Scheme + "://" + parsedURL.Host
		baseDomains[baseDomain] = true
	}

	log.Printf("Fuzzing %d base domains for hidden parameters...", len(baseDomains))
	
	domainIndex := 0
	for baseDomain := range baseDomains {
		domainIndex++
		log.Printf("Processing domain %d/%d: %s", domainIndex, len(baseDomains), baseDomain)
		
		request := paramsmapper.Request{
			URL:     baseDomain,
			Method:  "GET",
			Timeout: 10,
		}
		
		results := paramsmapper.DiscoverParamsWithProgress(request, wordlistParams, 500, func(progress paramsmapper.ProgressInfo) {
			// Only log significant progress updates
			if progress.Percentage%25 == 0 {
				log.Printf("Domain %d/%d - %s (discovered: %d)", domainIndex, len(baseDomains), progress.Message, progress.Discovered)
			}
		})
		
		// Merge results
		allResults.Params = append(allResults.Params, results.Params...)
		allResults.FormParams = append(allResults.FormParams, results.FormParams...)
		allResults.TotalRequests += results.TotalRequests
	}

	// Remove duplicates
	allResults.Params = removeDuplicates(allResults.Params)
	allResults.FormParams = removeDuplicates(allResults.FormParams)

	log.Printf("Parameter fuzzing complete: %d unique parameters discovered", len(allResults.Params))

	// Generate hidden URLs with discovered parameters
	for _, param := range allResults.Params {
		for _, baseURL := range crawl.URLs {
			hiddenURL := generateURLWithParam(baseURL, param)
			hiddenURLs = append(hiddenURLs, hiddenURL)
		}
	}

	log.Printf("Generated %d hidden URLs with discovered parameters", len(hiddenURLs))
	allURLs = append(allURLs, hiddenURLs...)

	// Skip saving URLs - only XSS vulnerabilities needed

	// 4) XSS Scanning
	log.Println("Phase 4: XSS scanning...")
	scanCfg := &scanner.Config{
		Quiet:     false,
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

	log.Printf("Starting XSS scan of %d URLs with concurrency %d", len(allURLs), *concurrency)

	for i, u := range allURLs {
		u := u
		urlIndex := i + 1
		sem <- struct{}{}
		count++
		go func() {
			defer func() { 
				<-sem
				mu.Lock()
				completed++
				log.Printf("XSS scan progress: %d/%d URLs completed", completed, len(allURLs))
				mu.Unlock()
				done <- struct{}{} 
			}()
			
			log.Printf("Scanning URL %d/%d: %s", urlIndex, len(allURLs), u)
			cfg := *scanCfg
			cfg.URL = u
			s := scanner.NewScanner(&cfg)
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()
			result, err := s.Scan(ctx)
			if err != nil {
				log.Printf("XSS scan error for %s: %v", u, err)
				return
			}
			if result != nil && len(result.Vulnerabilities) > 0 {
				mu.Lock()
				vulnerabilities = append(vulnerabilities, result.Vulnerabilities...)
				log.Printf("Found %d XSS vulnerabilities in %s", len(result.Vulnerabilities), u)
				mu.Unlock()
			}
		}()
	}

	for i := 0; i < count; i++ {
		<-done
	}

	// Save XSS results
	if err := saveXSSResults(vulnerabilities, outputFile); err != nil {
		log.Printf("Warning: Failed to save XSS results: %v", err)
	}

	// Skip generating summary - only XSS vulnerabilities needed

	log.Printf("Scan complete! XSS vulnerabilities saved to: %s", outputFile)
	log.Printf("Summary: %d URLs crawled, %d parameters found, %d hidden URLs discovered, %d XSS vulnerabilities found", 
		len(crawl.URLs), len(allParams), len(hiddenURLs), len(vulnerabilities))
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

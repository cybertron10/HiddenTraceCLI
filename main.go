package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"hiddentrace-cli/internal/crawler/crawler"
	"hiddentrace-cli/internal/scanner"
)

func main() {
	var (
		targetURL   = flag.String("url", "", "Target URL or domain to scan")
		concurrency = flag.Int("concurrency", 5, "Concurrent scans")
		headless    = flag.Bool("headless", true, "Use headless browser")
		fast       = flag.Bool("fast-mode", false, "Fast mode payload set")
		ultra      = flag.Bool("ultra-fast", false, "Ultra fast mode")
		timeout     = flag.Duration("timeout", 10*time.Minute, "Scan timeout")
	)
	flag.Parse()

	if *targetURL == "" {
		fmt.Println("Usage: hiddentrace-cli -url https://example.com [options]")
		flag.PrintDefaults()
		return
	}

	// 1) Crawl
	c := crawler.NewCrawler()
	crawl, err := c.CrawlDomain(*targetURL, map[string]string{})
	if err != nil {
		log.Fatalf("crawl error: %v", err)
	}
	log.Printf("Crawl: %d URLs discovered", len(crawl.URLs))

	// 2) Scan all discovered URLs
	scanCfg := &scanner.Config{
		Quiet:     false,
		Headless:  *headless,
		FastMode:  *fast,
		UltraFast: *ultra,
		Timeout:   *timeout,
	}

	sem := make(chan struct{}, *concurrency)
	done := make(chan struct{})
	count := 0

	for _, u := range crawl.URLs {
		u := u
		sem <- struct{}{}
		count++
		go func() {
			defer func() { <-sem; done <- struct{}{} }()
			cfg := *scanCfg
			cfg.URL = u
			s := scanner.NewScanner(&cfg)
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			defer cancel()
			if _, err := s.Scan(ctx); err != nil {
				log.Printf("scan error: %v", err)
			}
		}()
	}

	for i := 0; i < count; i++ {
		<-done
	}

	log.Println("Scan complete")
}

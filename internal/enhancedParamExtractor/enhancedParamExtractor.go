package enhancedParamExtractor

import (
	"net/url"
	"sort"
	"strings"

	"hiddentrace-cli/internal/crawler/crawler"
)

// ExtractAllParameters extracts parameters from all sources
func ExtractAllParameters(result *crawler.CrawlResult) []string {
	paramSet := make(map[string]bool)
	
	// Extract from URLs (existing functionality)
	for _, u := range result.URLs {
		parsedURL, err := url.Parse(u)
		if err != nil {
			continue
		}
		
		// Extract parameters from query string
		queryParams := parsedURL.Query()
		for param := range queryParams {
			cleanParam := cleanParameterName(param)
			if cleanParam != "" {
				paramSet[cleanParam] = true
			}
		}
		
		// Extract from fragment
		if parsedURL.Fragment != "" {
			fragmentParams := extractFromFragment(parsedURL.Fragment)
			for _, param := range fragmentParams {
				cleanParam := cleanParameterName(param)
				if cleanParam != "" {
					paramSet[cleanParam] = true
				}
			}
		}
	}
	
	// Extract from discovered parameters in crawl result
	for _, params := range result.Parameters {
		for _, param := range params {
			cleanParam := cleanParameterName(param.Name)
			if cleanParam != "" {
				paramSet[cleanParam] = true
			}
		}
	}
	
	// Convert map to slice
	var parameters []string
	for param := range paramSet {
		parameters = append(parameters, param)
	}
	
	// Sort parameters for consistent output
	sort.Strings(parameters)
	
	return parameters
}

// cleanParameterName cleans and validates parameter names
func cleanParameterName(param string) string {
	// Remove whitespace
	param = strings.TrimSpace(param)
	
	// Skip empty parameters
	if param == "" {
		return ""
	}
	
	// Skip parameters that are too long (likely not real parameters)
	if len(param) > 100 {
		return ""
	}
	
	// Skip parameters with suspicious characters
	if strings.ContainsAny(param, "<>\"'&") {
		return ""
	}
	
	return param
}

// extractFromFragment extracts parameters from URL fragment
func extractFromFragment(fragment string) []string {
	var params []string
	
	// Look for common parameter patterns in fragments
	// This is a simplified implementation
	if strings.Contains(fragment, "=") {
		parts := strings.Split(fragment, "&")
		for _, part := range parts {
			if strings.Contains(part, "=") {
				paramParts := strings.SplitN(part, "=", 2)
				if len(paramParts) > 0 {
					params = append(params, paramParts[0])
				}
			}
		}
	}
	
	return params
}
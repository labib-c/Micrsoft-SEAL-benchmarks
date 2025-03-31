package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// OASDocument represents an OpenAPI Specification document
type OASDocument struct {
	OpenAPI    string                 `json:"openapi" yaml:"openapi"`
	Info       map[string]interface{} `json:"info" yaml:"info"`
	Servers    []interface{}          `json:"servers,omitempty" yaml:"servers,omitempty"`
	Paths      map[string]interface{} `json:"paths" yaml:"paths"`
	Components map[string]interface{} `json:"components,omitempty" yaml:"components,omitempty"`
}

// PluginInfo stores information about Kong plugins
type PluginInfo struct {
	Name     string
	Priority int
	Path     string
	Method   string
	Config   map[string]interface{}
}

// Mapping of plugin names to their priority (lower number = higher priority)
var pluginPriorities = map[string]int{
	// Authentication plugins (highest priority)
	"key-auth":      10,
	"jwt":           11,
	"basic-auth":    12,
	"oauth2":        13,
	
	// Security plugins
	"ip-restriction": 20,
	"acl":            21,
	"rate-limiting":  22,
	
	// Request transformation
	"request-transformer": 30,
	"request-validator":   31,
	
	// Response transformation
	"response-transformer": 40,
	"cors":                 41,
	
	// Logging/Analytics (lowest priority)
	"http-log":    90,
	"file-log":    91,
	"prometheus":  92,
}

// GroupCategory determines the test category based on plugin priority
func pluginCategory(priority int) string {
	if priority < 20 {
		return "auth"
	} else if priority < 30 {
		return "security"
	} else if priority < 40 {
		return "request-transform"
	} else if priority < 50 {
		return "response-transform"
	} else if priority >= 90 {
		return "logging"
	}
	return "other"
}

// getPluginsFromOperation extracts Kong plugins from an OpenAPI operation
func getPluginsFromOperation(operation map[string]interface{}, path, method string) []PluginInfo {
	plugins := []PluginInfo{}
	
	for key, value := range operation {
		if strings.HasPrefix(key, "x-kong-plugin-") {
			pluginName := strings.TrimPrefix(key, "x-kong-plugin-")
			config, ok := value.(map[string]interface{})
			if !ok {
				// Handle non-map configs (could be bool, string, etc.)
				config = map[string]interface{}{"value": value}
			}
			
			priority, exists := pluginPriorities[pluginName]
			if !exists {
				priority = 50 // Default priority for unknown plugins
			}
			
			plugins = append(plugins, PluginInfo{
				Name:     pluginName,
				Priority: priority,
				Path:     path,
				Method:   method,
				Config:   config,
			})
		}
	}
	
	// Sort plugins by priority
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Priority < plugins[j].Priority
	})
	
	return plugins
}

// splitOASByPlugin divides the OAS by plugin type
func splitOASByPlugin(doc OASDocument) map[string]OASDocument {
	result := make(map[string]OASDocument)
	
	// Create a base document for routes without plugins
	baseDoc := OASDocument{
		OpenAPI: doc.OpenAPI,
		Info:    doc.Info,
		Servers: doc.Servers,
		Paths:   make(map[string]interface{}),
	}
	
	if doc.Components != nil {
		baseDoc.Components = doc.Components
	}
	
	// Group documents by plugin category
	categoryDocs := make(map[string]OASDocument)
	
	// Initialize documents for each category
	categories := []string{"auth", "security", "request-transform", "response-transform", "logging", "other"}
	for _, category := range categories {
		categoryDocs[category] = OASDocument{
			OpenAPI: doc.OpenAPI,
			Info:    mergeMaps(doc.Info, map[string]interface{}{
				"title":       fmt.Sprintf("%s - %s Tests", doc.Info["title"], strings.Title(category)),
				"description": fmt.Sprintf("OpenAPI spec for testing %s plugins", category),
			}),
			Servers: doc.Servers,
			Paths:   make(map[string]interface{}),
		}
		
		if doc.Components != nil {
			categoryDocs[category].Components = doc.Components
		}
	}
	
	// Group paths by the plugins they use
	for path, pathItemInterface := range doc.Paths {
		pathItem, ok := pathItemInterface.(map[string]interface{})
		if !ok {
			continue
		}
		
		// Track if this path has been added to any category
		pathAdded := false
		
		for method, operationInterface := range pathItem {
			// Skip non-operation fields like parameters
			if method == "parameters" {
				continue
			}
			
			operation, ok := operationInterface.(map[string]interface{})
			if !ok {
				continue
			}
			
			// Extract plugins from the operation
			plugins := getPluginsFromOperation(operation, path, method)
			
			if len(plugins) == 0 {
				// No plugins - add to base document
				ensurePath(baseDoc.Paths, path, method, operation)
				pathAdded = true
			} else {
				// Group by plugin category
				for _, plugin := range plugins {
					category := pluginCategory(plugin.Priority)
					
					// Ensure the path exists in the category document
					if categoryDocs[category].Paths[path] == nil {
						categoryDocs[category].Paths[path] = make(map[string]interface{})
					}
					
					// Copy the path item to the category document
					ensurePath(categoryDocs[category].Paths, path, method, operation)
					pathAdded = true
				}
			}
		}
		
		// If path wasn't added to any category, add it to the base document
		if !pathAdded {
			baseDoc.Paths[path] = pathItem
		}
	}
	
	// Add base document to result
	result["base"] = baseDoc
	
	// Add category documents to result (only if they have paths)
	for category, doc := range categoryDocs {
		if len(doc.Paths) > 0 {
			result[category] = doc
		}
	}
	
	return result
}

// createIndependentPluginDocs creates separate OAS documents for each plugin type
func createIndependentPluginDocs(doc OASDocument) map[string]OASDocument {
	result := make(map[string]OASDocument)
	
	// Map to collect paths by plugin
	pluginPaths := make(map[string]map[string]map[string]interface{})
	
	// Scan all paths and operations for plugins
	for path, pathItemInterface := range doc.Paths {
		pathItem, ok := pathItemInterface.(map[string]interface{})
		if !ok {
			continue
		}
		
		for method, operationInterface := range pathItem {
			// Skip non-operation fields
			if method == "parameters" {
				continue
			}
			
			operation, ok := operationInterface.(map[string]interface{})
			if !ok {
				continue
			}
			
			// Extract plugins
			plugins := getPluginsFromOperation(operation, path, method)
			
			for _, plugin := range plugins {
				// Initialize map for this plugin if needed
				if pluginPaths[plugin.Name] == nil {
					pluginPaths[plugin.Name] = make(map[string]map[string]interface{})
				}
				
				// Initialize map for this path if needed
				if pluginPaths[plugin.Name][path] == nil {
					pluginPaths[plugin.Name][path] = make(map[string]interface{})
					
					// Copy parameters if they exist at the path level
					if params, exists := pathItem["parameters"]; exists {
						pluginPaths[plugin.Name][path]["parameters"] = params
					}
				}
				
				// Add the operation to this plugin's paths
				pluginPaths[plugin.Name][path][method] = operation
			}
		}
	}
	
	// Create a document for each plugin
	for pluginName, paths := range pluginPaths {
		pluginDoc := OASDocument{
			OpenAPI: doc.OpenAPI,
			Info:    mergeMaps(doc.Info, map[string]interface{}{
				"title":       fmt.Sprintf("%s - %s Plugin Tests", doc.Info["title"], pluginName),
				"description": fmt.Sprintf("OpenAPI spec for testing the %s plugin", pluginName),
			}),
			Servers: doc.Servers,
			Paths:   paths,
		}
		
		if doc.Components != nil {
			pluginDoc.Components = doc.Components
		}
		
		result[pluginName] = pluginDoc
	}
	
	return result
}

// Helper function to ensure a path exists and add an operation to it
func ensurePath(paths map[string]interface{}, path, method string, operation map[string]interface{}) {
	if paths[path] == nil {
		paths[path] = make(map[string]interface{})
	}
	
	pathItem, ok := paths[path].(map[string]interface{})
	if !ok {
		pathItem = make(map[string]interface{})
		paths[path] = pathItem
	}
	
	pathItem[method] = operation
}

// Helper function to merge two maps
func mergeMaps(m1, m2 map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	
	// Copy m1
	for k, v := range m1 {
		result[k] = v
	}
	
	// Add/override with m2
	for k, v := range m2 {
		result[k] = v
	}
	
	return result
}

// writeOASToFile writes an OAS document to a file in YAML or JSON format
func writeOASToFile(doc OASDocument, filePath string) error {
	var data []byte
	var err error
	
	ext := strings.ToLower(filepath.Ext(filePath))
	
	if ext == ".json" {
		data, err = json.MarshalIndent(doc, "", "  ")
	} else {
		// Default to YAML
		data, err = yaml.Marshal(doc)
	}
	
	if err != nil {
		return err
	}
	
	return ioutil.WriteFile(filePath, data, 0644)
}

func main() {
	// Parse command line flags
	inputFile := flag.String("input", "", "Input OpenAPI specification file (YAML or JSON)")
	outputDir := flag.String("output", "split-oas", "Output directory for split OAS files")
	splitBy := flag.String("split-by", "category", "How to split the OAS (category or plugin)")
	flag.Parse()
	
	if *inputFile == "" {
		fmt.Println("Error: Input file is required")
		flag.PrintDefaults()
		os.Exit(1)
	}
	
	// Read the input file
	data, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		fmt.Printf("Error reading input file: %v\n", err)
		os.Exit(1)
	}
	
	// Parse the OpenAPI document
	var doc OASDocument
	ext := strings.ToLower(filepath.Ext(*inputFile))
	
	if ext == ".json" {
		err = json.Unmarshal(data, &doc)
	} else {
		// Default to YAML
		err = yaml.Unmarshal(data, &doc)
	}
	
	if err != nil {
		fmt.Printf("Error parsing OpenAPI document: %v\n", err)
		os.Exit(1)
	}
	
	// Create output directory if it doesn't exist
	err = os.MkdirAll(*outputDir, 0755)
	if err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}
	
	var splitDocs map[string]OASDocument
	
	// Split the document based on the specified method
	if *splitBy == "plugin" {
		splitDocs = createIndependentPluginDocs(doc)
	} else {
		splitDocs = splitOASByPlugin(doc)
	}
	
	// Write each document to a file
	for name, splitDoc := range splitDocs {
		fileName := filepath.Join(*outputDir, fmt.Sprintf("%s.yaml", name))
		err = writeOASToFile(splitDoc, fileName)
		if err != nil {
			fmt.Printf("Error writing to %s: %v\n", fileName, err)
			continue
		}
		fmt.Printf("Created %s\n", fileName)
	}
	
	fmt.Printf("Split complete. Generated %d OAS files in %s\n", len(splitDocs), *outputDir)
}

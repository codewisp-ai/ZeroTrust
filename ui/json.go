package ui

import (
	"encoding/json"
	"io"
	"zerotrust/detect"
)

// JSONSummary holds summary counts for JSON output.
type JSONSummary struct {
	TotalDependencies int `json:"total_dependencies"`
	PhantomCount      int `json:"phantom_count"`
	TyposquatCount    int `json:"typosquat_count"`
	HookCount         int `json:"hook_count"`
	EntropyCount      int `json:"entropy_count"`
	TokenCount        int `json:"token_count"`
	TotalRisks        int `json:"total_risks"`
}

// JSONFinding represents a single standardized finding in JSON output.
type JSONFinding struct {
	Category    string `json:"category"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	PackageName string `json:"package_name,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	SourceFile  string `json:"source_file"`
	LineNumber  int    `json:"line_number,omitempty"`
	Details     string `json:"details"`
}

// JSONReport represents the top-level JSON report structure.
type JSONReport struct {
	Summary  JSONSummary   `json:"summary"`
	Findings []JSONFinding `json:"findings"`
}

// BuildJSONReport converts an AuditReport into a JSONReport structure.
func BuildJSONReport(report *detect.AuditReport) *JSONReport {
	var findings []JSONFinding

	for _, p := range report.PhantomFindings {
		findings = append(findings, JSONFinding{
			Category:    "phantom",
			Ecosystem:   p.Dependency.Ecosystem,
			PackageName: p.Dependency.Name,
			Confidence:  p.Confidence,
			SourceFile:  p.Dependency.SourceFile,
			LineNumber:  p.Dependency.LineNumber,
			Details:     p.Details,
		})
	}

	for _, t := range report.TyposquatFindings {
		findings = append(findings, JSONFinding{
			Category:    "typosquat",
			Ecosystem:   t.Dependency.Ecosystem,
			PackageName: t.Dependency.Name,
			SourceFile:  t.Dependency.SourceFile,
			LineNumber:  t.Dependency.LineNumber,
			Details:     t.Details,
		})
	}

	for _, h := range report.HookFindings {
		findings = append(findings, JSONFinding{
			Category:   "hook",
			Ecosystem:  h.Ecosystem,
			SourceFile: h.SourceFile,
			Details:    h.Details,
		})
	}

	for _, e := range report.EntropyFindings {
		findings = append(findings, JSONFinding{
			Category:   "entropy",
			SourceFile: e.FilePath,
			Details:    e.Details,
		})
	}

	for _, tok := range report.TokenFindings {
		findings = append(findings, JSONFinding{
			Category:   "token",
			SourceFile: tok.FilePath,
			LineNumber: tok.LineNumber,
			Details:    tok.Details,
		})
	}

	totalRisks := len(findings)

	return &JSONReport{
		Summary: JSONSummary{
			TotalDependencies: len(report.Dependencies),
			PhantomCount:      len(report.PhantomFindings),
			TyposquatCount:    len(report.TyposquatFindings),
			HookCount:         len(report.HookFindings),
			EntropyCount:      len(report.EntropyFindings),
			TokenCount:        len(report.TokenFindings),
			TotalRisks:        totalRisks,
		},
		Findings: findings,
	}
}

// RenderJSONReport encodes the audit findings as formatted JSON to w.
func RenderJSONReport(report *detect.AuditReport, w io.Writer) error {
	jr := BuildJSONReport(report)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}

// SARIF Structures for SARIF 2.1.0 output subset
type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string    `json:"id"`
	ShortDescription SarifText `json:"shortDescription"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SarifText       `json:"message"`
	Locations []SarifLocation `json:"locations"`
}

type SarifText struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine"`
}

// RenderSARIFReport encodes the audit findings as a valid SARIF 2.1.0 document.
func RenderSARIFReport(report *detect.AuditReport, w io.Writer) error {
	rules := []SarifRule{
		{ID: "ZT001", ShortDescription: SarifText{Text: "AI-Hallucinated / Non-Existent Package (Phantom)"}},
		{ID: "ZT002", ShortDescription: SarifText{Text: "Typosquatted Dependency Candidate"}},
		{ID: "ZT003", ShortDescription: SarifText{Text: "Lifecycle Install Hook Execution"}},
		{ID: "ZT004", ShortDescription: SarifText{Text: "High-Entropy Obfuscated Binary Payload"}},
		{ID: "ZT005", ShortDescription: SarifText{Text: "Dynamic Code Execution Token"}},
	}

	var results []SarifResult

	jr := BuildJSONReport(report)
	for _, f := range jr.Findings {
		ruleID := "ZT001"
		level := "warning"

		switch f.Category {
		case "phantom":
			ruleID = "ZT001"
			level = "error"
		case "typosquat":
			ruleID = "ZT002"
			level = "warning"
		case "hook":
			ruleID = "ZT003"
			level = "error"
		case "entropy":
			ruleID = "ZT004"
			level = "warning"
		case "token":
			ruleID = "ZT005"
			level = "warning"
		}

		line := f.LineNumber
		if line <= 0 {
			line = 1
		}

		res := SarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SarifText{Text: f.Details},
			Locations: []SarifLocation{
				{
					PhysicalLocation: SarifPhysicalLocation{
						ArtifactLocation: SarifArtifactLocation{URI: f.SourceFile},
						Region:           SarifRegion{StartLine: line},
					},
				},
			},
		}

		results = append(results, res)
	}

	log := SarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "ZeroTrust",
						Version:        "1.0.0",
						InformationURI: "https://github.com/zerotrust/zerotrust",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

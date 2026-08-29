package ui

import (
	"fmt"
	"io"
	"os"

	"strings"
	"text/template"

	"zerotrust/detect"
)

// RenderTerminalReport prints a styled security audit report to stdout.
func RenderTerminalReport(report *detect.AuditReport, useColor bool) {
	fmt.Println()
	fmt.Println(Colorize("================================================================================", BoldCyan, useColor))
	fmt.Println(Colorize("                    ZEROTRUST SUPPLY-CHAIN SECURITY AUDIT                       ", BoldCyan, useColor))
	fmt.Println(Colorize("================================================================================", BoldCyan, useColor))
	fmt.Println()

	fmt.Printf("Total Dependencies Evaluated : %d\n", len(report.Dependencies))
	fmt.Printf("Phantom Findings              : %s\n", formatCount(len(report.PhantomFindings), BoldRed, useColor))
	fmt.Printf("Typosquat Findings            : %s\n", formatCount(len(report.TyposquatFindings), BoldYel, useColor))
	fmt.Printf("Lifecycle Hook Findings       : %s\n", formatCount(len(report.HookFindings), BoldRed, useColor))
	fmt.Printf("High Entropy Payload Findings : %s\n", formatCount(len(report.EntropyFindings), BoldYel, useColor))
	fmt.Printf("Dynamic Exec Token Findings   : %s\n", formatCount(len(report.TokenFindings), BoldYel, useColor))
	fmt.Println()

	// 1. Phantom Findings Section
	if len(report.PhantomFindings) > 0 {
		fmt.Println(Colorize("--- [PHANTOM / HALLUCINATED PACKAGES] ---", BoldRed, useColor))
		headers := []string{"ECOSYSTEM", "PACKAGE NAME", "CONFIDENCE", "SOURCE FILE"}
		var rows [][]string
		for _, p := range report.PhantomFindings {
			confBadge := Badge(p.Confidence, Red, useColor)
			if strings.Contains(p.Confidence, "HIGH") {
				confBadge = Badge(p.Confidence, BoldRed, useColor)
			}
			rows = append(rows, []string{
				p.Dependency.Ecosystem,
				Colorize(p.Dependency.Name, BoldRed, useColor),
				confBadge,
				p.Dependency.SourceFile,
			})
		}
		fmt.Print(FormatTable(headers, rows))
		fmt.Println()
	}

	// 2. Typosquat Findings Section
	if len(report.TyposquatFindings) > 0 {
		fmt.Println(Colorize("--- [TYPOSQUAT CANDIDATES] ---", BoldYel, useColor))
		headers := []string{"ECOSYSTEM", "DECLARED DEP", "TARGET POPULAR PKG", "EDIT DIST", "SOURCE FILE"}
		var rows [][]string
		for _, t := range report.TyposquatFindings {
			rows = append(rows, []string{
				t.Dependency.Ecosystem,
				Colorize(t.Dependency.Name, BoldYel, useColor),
				Colorize(t.TargetPackage, Green, useColor),
				fmt.Sprintf("%d", t.EditDistance),
				t.Dependency.SourceFile,
			})
		}
		fmt.Print(FormatTable(headers, rows))
		fmt.Println()
	}

	// 3. Lifecycle Hooks Section
	if len(report.HookFindings) > 0 {
		fmt.Println(Colorize("--- [LIFECYCLE INSTALL HOOKS] ---", BoldRed, useColor))
		headers := []string{"ECOSYSTEM", "HOOK", "COMMAND", "FILE"}
		var rows [][]string
		for _, h := range report.HookFindings {
			rows = append(rows, []string{
				h.Ecosystem,
				Colorize(h.HookName, Red, useColor),
				h.Command,
				h.SourceFile,
			})
		}
		fmt.Print(FormatTable(headers, rows))
		fmt.Println()
	}

	// 4. Shannon Entropy Section
	if len(report.EntropyFindings) > 0 {
		fmt.Println(Colorize("--- [HIGH-ENTROPY OBFUSCATED PAYLOADS] ---", BoldYel, useColor))
		headers := []string{"FILE", "MAX ENTROPY", "OFFSET", "DETAILS"}
		var rows [][]string
		for _, e := range report.EntropyFindings {
			rows = append(rows, []string{
				e.FilePath,
				fmt.Sprintf("%.2f bits/byte", e.MaxEntropy),
				fmt.Sprintf("%d", e.Offset),
				e.Details,
			})
		}
		fmt.Print(FormatTable(headers, rows))
		fmt.Println()
	}

	// 5. Dynamic Exec Token Section
	if len(report.TokenFindings) > 0 {
		fmt.Println(Colorize("--- [LEXICAL DYNAMIC EXEC TOKENS] ---", BoldYel, useColor))
		headers := []string{"FILE:LINE", "PATTERN", "LINE SNIPPET"}
		var rows [][]string
		for _, tok := range report.TokenFindings {
			rows = append(rows, []string{
				fmt.Sprintf("%s:%d", tok.FilePath, tok.LineNumber),
				Colorize(tok.Pattern, Red, useColor),
				tok.LineSnippet,
			})
		}
		fmt.Print(FormatTable(headers, rows))
		fmt.Println()
	}

	totalIssues := len(report.PhantomFindings) + len(report.TyposquatFindings) +
		len(report.HookFindings) + len(report.EntropyFindings) + len(report.TokenFindings)

	if totalIssues == 0 {
		fmt.Println(Badge("PASS: ZERO HIGH-RISK SUPPLY CHAIN ISSUES DETECTED", BoldGreen, useColor))
	} else {
		fmt.Printf(Badge("AUDIT COMPLETE: %d TOTAL POTENTIAL RISKS IDENTIFIED", BoldRed, useColor)+"\n", totalIssues)
	}
	fmt.Println()
}

func formatCount(count int, color string, useColor bool) string {
	if count == 0 {
		return Colorize("0 (Clean)", Green, useColor)
	}
	return Colorize(fmt.Sprintf("%d Flagged", count), color, useColor)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroTrust Supply-Chain Security Audit Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }
        .container { max-width: 1100px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
        h1 { color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 12px; margin-top: 0; }
        h2 { color: #f43f5e; margin-top: 32px; border-bottom: 1px solid #334155; padding-bottom: 8px; }
        table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }
        th { background: #334155; text-align: left; padding: 12px; color: #94a3b8; }
        td { padding: 12px; border-bottom: 1px solid #334155; }
        tr:hover { background: #283548; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .badge-red { background: #881337; color: #fecdd3; }
        .badge-yellow { background: #713f12; color: #fef08a; }
        .badge-green { background: #14532d; color: #bbf7d0; }
        .summary-box { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }
        .card { background: #0f172a; padding: 20px; border-radius: 8px; border: 1px solid #334155; }
        .card-num { font-size: 28px; font-weight: bold; margin-top: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ZeroTrust Security Audit Report</h1>
        <p>Offline-First Zero-Dependency Supply-Chain Scanner</p>
        
        <div class="summary-box">
            <div class="card"><div>Evaluated Dependencies</div><div class="card-num" style="color:#38bdf8">{{len .Dependencies}}</div></div>
            <div class="card"><div>Phantom Packages</div><div class="card-num" style="color:#f43f5e">{{len .PhantomFindings}}</div></div>
            <div class="card"><div>Typosquats</div><div class="card-num" style="color:#facc15">{{len .TyposquatFindings}}</div></div>
            <div class="card"><div>Lifecycle Hooks</div><div class="card-num" style="color:#fb7185">{{len .HookFindings}}</div></div>
            <div class="card"><div>Obfuscated Payloads</div><div class="card-num" style="color:#eab308">{{len .EntropyFindings}}</div></div>
        </div>

        {{if .PhantomFindings}}
        <h2>Phantom / Hallucinated Packages</h2>
        <table>
            <tr><th>Ecosystem</th><th>Package Name</th><th>Confidence</th><th>Source File</th></tr>
            {{range .PhantomFindings}}
            <tr>
                <td>{{.Dependency.Ecosystem}}</td>
                <td><strong style="color:#f43f5e">{{.Dependency.Name}}</strong></td>
                <td><span class="badge badge-red">{{.Confidence}}</span></td>
                <td>{{.Dependency.SourceFile}}</td>
            </tr>
            {{end}}
        </table>
        {{end}}

        {{if .TyposquatFindings}}
        <h2>Typosquat Candidates</h2>
        <table>
            <tr><th>Ecosystem</th><th>Declared Dep</th><th>Popular Target Package</th><th>Edit Dist</th><th>Source File</th></tr>
            {{range .TyposquatFindings}}
            <tr>
                <td>{{.Dependency.Ecosystem}}</td>
                <td><strong style="color:#facc15">{{.Dependency.Name}}</strong></td>
                <td><span style="color:#4ade80">{{.TargetPackage}}</span></td>
                <td>{{.EditDistance}}</td>
                <td>{{.Dependency.SourceFile}}</td>
            </tr>
            {{end}}
        </table>
        {{end}}

        {{if .HookFindings}}
        <h2>Lifecycle Install Hooks</h2>
        <table>
            <tr><th>Ecosystem</th><th>Hook Name</th><th>Command</th><th>Source File</th></tr>
            {{range .HookFindings}}
            <tr>
                <td>{{.Ecosystem}}</td>
                <td><span class="badge badge-red">{{.HookName}}</span></td>
                <td><code>{{.Command}}</code></td>
                <td>{{.SourceFile}}</td>
            </tr>
            {{end}}
        </table>
        {{end}}

        {{if .EntropyFindings}}
        <h2>High Entropy Payload Blocks</h2>
        <table>
            <tr><th>File Path</th><th>Max Entropy</th><th>Offset</th><th>Details</th></tr>
            {{range .EntropyFindings}}
            <tr>
                <td>{{.FilePath}}</td>
                <td>{{printf "%.2f" .MaxEntropy}} bits/byte</td>
                <td>{{.Offset}}</td>
                <td>{{.Details}}</td>
            </tr>
            {{end}}
        </table>
        {{end}}

        {{if .TokenFindings}}
        <h2>Dynamic Exec Tokens</h2>
        <table>
            <tr><th>File & Line</th><th>Pattern</th><th>Snippet</th></tr>
            {{range .TokenFindings}}
            <tr>
                <td>{{.FilePath}}:{{.LineNumber}}</td>
                <td><span class="badge badge-yellow">{{.Pattern}}</span></td>
                <td><code>{{.LineSnippet}}</code></td>
            </tr>
            {{end}}
        </table>
        {{end}}

    </div>
</body>
</html>`

// RenderHTMLReport generates a static HTML report file.
func RenderHTMLReport(report *detect.AuditReport, outputPath string) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, report)
}

// Ensure interface compatibility for io.Writer testing
var _ io.Writer = (*os.File)(nil)

package detect

import (
	"sync"

	"zerotrust/manifest"
)

// AuditReport aggregates findings across all detection modules.
type AuditReport struct {
	Dependencies      []manifest.Dependency
	PhantomFindings   []PhantomFinding
	TyposquatFindings []TyposquatFinding
	EntropyFindings   []EntropyFinding
	HookFindings      []HookFinding
	TokenFindings     []TokenFinding
}

// Engine coordinates parallel execution of security detectors.
type Engine struct {
	phantom   *PhantomDetector
	typosquat *TyposquatDetector
	entropy   *EntropyScanner
	tokens    *TokenScanner
	workers   int
}

// NewEngine constructs a new concurrent scan Engine.
func NewEngine(p *PhantomDetector, t *TyposquatDetector, e *EntropyScanner, tok *TokenScanner, workers int) *Engine {
	if workers <= 0 {
		workers = 4
	}
	return &Engine{
		phantom:   p,
		typosquat: t,
		entropy:   e,
		tokens:    tok,
		workers:   workers,
	}
}

// AuditDependencies runs phantom and typosquat detection concurrently across all dependencies.
func (e *Engine) AuditDependencies(deps []manifest.Dependency) ([]PhantomFinding, []TyposquatFinding) {
	if len(deps) == 0 {
		return nil, nil
	}

	jobs := make(chan manifest.Dependency, len(deps))
	phantomsChan := make(chan PhantomFinding, len(deps))
	typosquatsChan := make(chan TyposquatFinding, len(deps))

	for _, d := range deps {
		jobs <- d
	}
	close(jobs)

	var wg sync.WaitGroup
	numWorkers := e.workers
	if numWorkers > len(deps) {
		numWorkers = len(deps)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dep := range jobs {
				if pf := e.phantom.Check(dep); pf != nil {
					phantomsChan <- *pf
				}
				if tf := e.typosquat.Check(dep); tf != nil {
					typosquatsChan <- *tf
				}
			}
		}()
	}

	wg.Wait()
	close(phantomsChan)
	close(typosquatsChan)

	var phantoms []PhantomFinding
	for pf := range phantomsChan {
		phantoms = append(phantoms, pf)
	}

	var typosquats []TyposquatFinding
	for tf := range typosquatsChan {
		typosquats = append(typosquats, tf)
	}

	return phantoms, typosquats
}

// FullAudit executes all detectors on a project directory and manifest dependencies.
func (e *Engine) FullAudit(deps []manifest.Dependency, targetPath string) (*AuditReport, error) {
	report := &AuditReport{
		Dependencies: deps,
	}

	var wg sync.WaitGroup

	// Task 1: Dependency scanning
	wg.Add(1)
	go func() {
		defer wg.Done()
		p, t := e.AuditDependencies(deps)
		report.PhantomFindings = p
		report.TyposquatFindings = t
	}()

	// Task 2: Lifecycle hooks
	wg.Add(1)
	go func() {
		defer wg.Done()
		if h, err := CheckInstallHooks(targetPath); err == nil {
			report.HookFindings = h
		}
	}()

	// Task 3: Shannon entropy scanning
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ent, err := e.entropy.ScanDirectory(targetPath); err == nil {
			report.EntropyFindings = ent
		}
	}()

	// Task 4: Lexical dynamic exec token scanning
	wg.Add(1)
	go func() {
		defer wg.Done()
		if tok, err := e.tokens.ScanDirectory(targetPath); err == nil {
			report.TokenFindings = tok
		}
	}()

	wg.Wait()
	return report, nil
}

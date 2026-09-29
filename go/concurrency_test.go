package applereceipt_test

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
)

// "Safe for concurrent use by multiple goroutines" is a claim on Verifier,
// and now a claim about a pool of module instances too. Run under -race in
// CI, this is what makes it a tested claim rather than a doc comment: every
// case of fixtures/cases.json is answered once on one goroutine, then
// again on several at once through the same Verifiers, and each goroutine
// must get the single-goroutine row for every case. Some cases trap the
// module or come back as INTERNAL_ERROR with a stand-in module; the rows
// still have to agree.

// caseRow is one case's outcome as a string: the payload JSON or the
// endpoint body when it answered, REASON: message when it failed.
func caseRow(t testing.TB, dir string, fixtures map[string]fixtureEntry, c conformanceCase, v *applereceipt.Verifier) string {
	switch c.Operation {
	case "verifyReceipt":
		payload, err := v.VerifyReceipt(receiptString(t, dir, fixtures, c.Input.Fixture))
		if err != nil {
			return err.Error()
		}
		return payload.ToJSON()
	case "verifySignedData":
		payload, err := v.VerifySignedData(string(fixtureBytesIn(t, dir, fixtures, c.Input.Fixture)))
		if err != nil {
			return err.Error()
		}
		return payload.JSON()
	case "verifyReceiptEndpoint":
		environment := applereceipt.EnvironmentSandbox
		if c.Config.Environment == "PRODUCTION" {
			environment = applereceipt.EnvironmentProduction
		}
		var body string
		if c.Input.RequestBody != "" {
			body = string(fixtureBytesIn(t, dir, fixtures, c.Input.RequestBody))
		} else {
			encoded, err := json.Marshal(map[string]string{"receipt-data": receiptString(t, dir, fixtures, c.Input.Fixture)})
			if err != nil {
				t.Fatal(err)
			}
			body = string(encoded)
		}
		return v.VerifyReceiptEndpoint(environment, body)
	}
	t.Fatalf("%s: no row for operation %q", c.ID, c.Operation)
	return ""
}

func TestVerifierIsSafeForConcurrentUse(t *testing.T) {
	dir, file := sharedCases(t)
	fixedClock := &clockSpec{Now: "2025-01-01T00:00:00Z"}
	verifiers := map[string]*applereceipt.Verifier{}
	var cases []conformanceCase
	for _, c := range file.Cases {
		if c.Operation == "decodeBase64" {
			continue
		}
		clock := c.Clock
		if clock == nil {
			clock = fixedClock
		}
		key := c.Config.TrustedRoots.Source + "|" + strings.Join(c.Config.TrustedRoots.Fixtures, ",") + "|" + clock.Now
		if verifiers[key] == nil {
			verifiers[key] = buildVerifier(t, buildConfig(t, dir, file.Fixtures, c.Config, clock))
		}
		c.Config = &caseConfigSpec{TrustedRoots: c.Config.TrustedRoots, Environment: c.Config.Environment}
		c.Clock = &clockSpec{Now: key[strings.LastIndex(key, "|")+1:]}
		cases = append(cases, c)
	}
	verifierOf := func(c conformanceCase) *applereceipt.Verifier {
		return verifiers[c.Config.TrustedRoots.Source+"|"+strings.Join(c.Config.TrustedRoots.Fixtures, ",")+"|"+c.Clock.Now]
	}

	want := make([]string, len(cases))
	for i, c := range cases {
		want[i] = caseRow(t, dir, file.Fixtures, c, verifierOf(c))
	}

	goroutines := 4
	if testing.Short() {
		goroutines = 2
	}
	var wg sync.WaitGroup
	errs := make(chan string, len(cases)*goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			// Each goroutine starts at a different case, so they meet
			// different inputs on the same Verifier at the same time.
			for n := range cases {
				i := (n + g*len(cases)/goroutines) % len(cases)
				if got := caseRow(t, dir, file.Fixtures, cases[i], verifierOf(cases[i])); got != want[i] {
					errs <- cases[i].ID + ": the answer on goroutine " + string(rune('0'+g)) + " differs from the single-goroutine row"
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for message := range errs {
		t.Error(message)
	}
	t.Logf("%d cases, %d goroutines, %d Verifiers", len(cases), goroutines, len(verifiers))
}

// The bundled root set is lazily initialised, so it gets its own race.
func TestAppleRootsIsSafeForConcurrentUse(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if len(applereceipt.AppleRoots()) != 3 {
					t.Error("the bundled root set changed size under concurrency")
					return
				}
			}
		}()
	}
	wg.Wait()
}

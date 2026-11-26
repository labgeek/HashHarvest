package readers

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// pdfWith builds a one-page PDF whose page draws form 5 and whose objects
// after the page are given verbatim.
func pdfWith(page string, objects ...string) []byte {
	var b strings.Builder
	b.WriteString("%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
	b.WriteString("2 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n")
	b.WriteString("3 0 obj << /Type /Page /Contents 4 0 R /Resources << /XObject << /F 5 0 R >> >> >> endobj\n")
	b.WriteString("4 0 obj << >>\nstream\n" + page + "\nendstream endobj\n")
	for i, o := range objects {
		fmt.Fprintf(&b, "%d 0 obj %s endobj\n", 5+i, o)
	}
	b.WriteString("trailer << /Root 1 0 R >>\n")
	return []byte(b.String())
}

// within fails the test if fn has not returned after limit. A parser that
// hangs on hostile input would otherwise hang the whole scan.
func within(t *testing.T, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("did not finish within %v", limit)
	}
}

// A form that draws itself ten times at every level: without a cap on the
// number of forms drawn this is 10^12 draws (a "billion laughs"). It must
// stop quickly and report the limit, like every other limit.
func TestPDFSelfDrawingFormFinishes(t *testing.T) {
	form := "<< /Type /XObject /Subtype /Form /Resources << /XObject << /F 5 0 R >> >> >>\nstream\n" +
		"BT (" + md5Hash + ") Tj ET" + strings.Repeat(" /F Do", 10) + "\nendstream"
	within(t, 5*time.Second, func() {
		_, err := pdfPageTexts(pdfWith("/F Do", form))
		if err == nil || err.Error() != "page 1: a PDF page draws more than 100000 forms" {
			t.Errorf("err = %v", err)
		}
	})
	// Many draws below the cap are fine.
	few := "<< /Subtype /Form >>\nstream\nBT (" + md5Hash + ") Tj ET\nendstream"
	pages, err := pdfPageTexts(pdfWith(strings.Repeat("/F Do ", 1000), few))
	if err != nil || strings.Count(pages[0], md5Hash) != 1000 {
		t.Errorf("1000 draws: %d hashes, %v", strings.Count(pages[0], md5Hash), err)
	}
}

func TestPDFStructuralLoopsFinish(t *testing.T) {
	cases := map[string][]byte{
		// Kids that point back up the tree.
		"page tree cycle": []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n" +
			"2 0 obj << /Type /Pages /Kids [2 0 R 3 0 R] >> endobj\n" +
			"3 0 obj << /Type /Pages /Kids [2 0 R] >> endobj\ntrailer << /Root 1 0 R >>\n"),
		// An object that is a reference to itself, used as the contents.
		"reference to itself": []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n" +
			"2 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n3 0 obj << /Type /Page /Contents 4 0 R >> endobj\n" +
			"4 0 obj 4 0 R endobj\ntrailer << /Root 1 0 R >>\n"),
		// Two forms drawing each other.
		"mutual forms": pdfWith("/F Do",
			"<< /Subtype /Form /Resources << /XObject << /F 6 0 R >> >> >>\nstream\n/F Do /F Do\nendstream",
			"<< /Subtype /Form /Resources << /XObject << /F 5 0 R >> >> >>\nstream\n/F Do /F Do\nendstream"),
		// A /Length far past the end of the file.
		"huge length": []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n" +
			"2 0 obj << /Type /Pages /Kids [3 0 R] >> endobj\n3 0 obj << /Type /Page /Contents 4 0 R >> endobj\n" +
			"4 0 obj << /Length 99999999999 >>\nstream\nBT (x) Tj ET\nendstream endobj\ntrailer << /Root 1 0 R >>\n"),
		// Thousands of nested arrays in a content stream.
		"deep operand nesting": pdfWith(strings.Repeat("[", 100000) + " Tj"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			within(t, 5*time.Second, func() { pdfPageTexts(data) })
		})
	}
}

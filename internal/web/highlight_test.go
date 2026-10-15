package web

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

var tags = regexp.MustCompile(`<span class="[a-z-]+">|</span>`)

func TestHighlight(t *testing.T) {
	for _, in := range []string{
		`<samlp:Response ID="_1" a='x>y'><saml:Issuer>https://idp</saml:Issuer><!-- c --></samlp:Response>`,
		`{"sub": "u1", "n": -1.5e3, "ok": true, "x": null, "s": "a\"b<script>"}`,
		`plain <b>text</b> & more`,
	} {
		out := string(highlight(in))
		// Only our spans are markup; everything else is escaped text that
		// reads back as the input.
		if got := html.UnescapeString(tags.ReplaceAllString(out, "")); got != in {
			t.Errorf("round trip:\n in  %s\n out %s", in, got)
		}
		if strings.Contains(tags.ReplaceAllString(out, ""), "<") {
			t.Errorf("unescaped markup in %s", out)
		}
	}
	x := string(highlight(`<a b="c">t</a>`))
	for _, want := range []string{`<span class="x-tag">&lt;a</span>`, `<span class="x-attr">b</span>`, `<span class="x-val">&#34;c&#34;</span>`} {
		if !strings.Contains(x, want) {
			t.Errorf("XML: missing %s in %s", want, x)
		}
	}
	j := string(highlight(`{"k": "v", "n": 2}`))
	if !strings.Contains(j, `<span class="j-key">&#34;k&#34;</span>`) || !strings.Contains(j, `<span class="j-str">&#34;v&#34;</span>`) || !strings.Contains(j, `<span class="j-lit">2</span>`) {
		t.Errorf("JSON: %s", j)
	}
}

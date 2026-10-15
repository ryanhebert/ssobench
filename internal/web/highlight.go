package web

import (
	"html"
	"html/template"
	"strings"
)

// highlight marks up XML or JSON for the code blocks, escaping every
// character and adding only spans with classes (the CSP allows no inline
// styles). Other text is just escaped.
func highlight(s string) template.HTML {
	t := strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(t, "<"):
		return template.HTML(highlightXML(s))
	case strings.HasPrefix(t, "{") || strings.HasPrefix(t, "["):
		return template.HTML(highlightJSON(s))
	}
	return template.HTML(html.EscapeString(s))
}

func span(class, text string) string {
	return `<span class="` + class + `">` + html.EscapeString(text) + `</span>`
}

func highlightXML(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			b.WriteString(html.EscapeString(s))
			break
		}
		b.WriteString(html.EscapeString(s[:i]))
		s = s[i:]
		if strings.HasPrefix(s, "<!--") {
			end := strings.Index(s, "-->")
			if end < 0 {
				end = len(s) - 3
			}
			b.WriteString(span("x-com", s[:end+3]))
			s = s[end+3:]
			continue
		}
		end := tagEnd(s)
		b.WriteString(xmlTag(s[:end]))
		s = s[end:]
	}
	return b.String()
}

// tagEnd is the length of the tag at the start of s, quotes respected.
func tagEnd(s string) int {
	var quote byte
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i + 1
		}
	}
	return len(s)
}

// xmlTag marks up one tag: its name, attribute names and values.
func xmlTag(tag string) string {
	var b strings.Builder
	i := 1
	for i < len(tag) && (tag[i] == '/' || tag[i] == '?' || tag[i] == '!') {
		i++
	}
	j := i
	for j < len(tag) && !strings.ContainsRune(" \t\r\n/>", rune(tag[j])) {
		j++
	}
	b.WriteString(span("x-tag", tag[:j]))
	rest := tag[j:]
	for len(rest) > 0 {
		c := rest[0]
		switch {
		case c == '"' || c == '\'':
			k := strings.IndexByte(rest[1:], c)
			if k < 0 {
				k = len(rest) - 2
			}
			b.WriteString(span("x-val", rest[:k+2]))
			rest = rest[k+2:]
		case strings.ContainsRune(" \t\r\n=", rune(c)):
			b.WriteString(html.EscapeString(rest[:1]))
			rest = rest[1:]
		case c == '/' || c == '>' || c == '?':
			b.WriteString(span("x-tag", rest))
			rest = ""
		default:
			k := 0
			for k < len(rest) && !strings.ContainsRune(" \t\r\n=/>", rune(rest[k])) {
				k++
			}
			b.WriteString(span("x-attr", rest[:k]))
			rest = rest[k:]
		}
	}
	return b.String()
}

func highlightJSON(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			j = min(j+1, len(s))
			k := j
			for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
				k++
			}
			class := "j-str"
			if k < len(s) && s[k] == ':' {
				class = "j-key"
			}
			b.WriteString(span(class, s[i:j]))
			i = j
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < len(s) && strings.ContainsRune("0123456789.eE+-", rune(s[j])) {
				j++
			}
			b.WriteString(span("j-lit", s[i:j]))
			i = j
		case strings.HasPrefix(s[i:], "true"), strings.HasPrefix(s[i:], "null"):
			b.WriteString(span("j-lit", s[i:i+4]))
			i += 4
		case strings.HasPrefix(s[i:], "false"):
			b.WriteString(span("j-lit", s[i:i+5]))
			i += 5
		default:
			b.WriteString(html.EscapeString(s[i : i+1]))
			i++
		}
	}
	return b.String()
}

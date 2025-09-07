package render

import (
	"regexp"
	"strings"
	"unicode"
)

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	user := parts[0]
	domainParts := strings.SplitN(parts[1], ".", 2)
	if len(domainParts) != 2 {
		return email
	}

	domain, tld := domainParts[0], domainParts[1]
	maskPart := func(s string) string {
		if len(s) <= 1 {
			return s
		} else if len(s) == 2 {
			return string(s[0]) + "*"
		}
		return string(s[0]) + strings.Repeat("*", len(s)-2) + string(s[len(s)-1])
	}
	return maskPart(user) + "@" + maskPart(domain) + "." + tld
}

func formatPhone(phone string) string {
	// strip non-digits
	re := regexp.MustCompile(`\D`)
	digits := re.ReplaceAllString(phone, "")
	if digits == "" {
		return phone
	}

	// drop country code
	if len(digits) > 10 {
		digits = digits[len(digits)-10:]
	}

	n := len(digits)
	if n == 10 {
		return digits[0:3] + " " + digits[3:6] + " " + digits[6:10]
	}

	parts := []string{}
	i := 0
	for i < n {
		rem := n - i
		if rem > 4 {
			parts = append(parts, digits[i:i+3])
			i += 3
		} else if rem == 4 {
			parts = append(parts, digits[i:i+2], digits[i+2:i+4])
			break
		} else {
			parts = append(parts, digits[i:])
			break
		}
	}
	return strings.Join(parts, " ")
}

func maskPhone(formatted string) string {
	var digitsOnly strings.Builder
	for _, ch := range formatted {
		if unicode.IsDigit(ch) {
			digitsOnly.WriteRune(ch)
		}
	}
	dStr := digitsOnly.String()
	n := len(dStr)
	if n == 0 {
		return formatted
	}

	var maskedDigits string
	if n <= 4 {
		maskedDigits = dStr[:1] + strings.Repeat("*", n-1)
	} else {
		maskedDigits = dStr[:2] + strings.Repeat("*", n-4) + dStr[n-2:]
	}

	// rebuild preserving spaces
	var result strings.Builder
	idx := 0
	for _, ch := range formatted {
		if unicode.IsDigit(ch) {
			result.WriteByte(maskedDigits[idx])
			idx++
		} else {
			result.WriteRune(ch)
		}
	}
	return result.String()
}

package state

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Money is an exact USD amount in billionths of a dollar. JSON uses decimal
// strings, so a consumer cannot accidentally round money through float64.
type Money int64

const Dollar Money = 1_000_000_000

func ParseMoney(s string) (Money, error) {
	if s == "" {
		return 0, fmt.Errorf("empty USD amount")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 || parts[0] == "" {
		return 0, fmt.Errorf("invalid USD amount %q", s)
	}
	for _, part := range parts {
		if part == "" {
			return 0, fmt.Errorf("invalid USD amount %q", s)
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("USD amount must be a nonnegative decimal")
			}
		}
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	if len(fraction) > 9 {
		return 0, fmt.Errorf("USD amount has more than 9 decimal places")
	}
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || whole > math.MaxInt64/int64(Dollar) {
		return 0, fmt.Errorf("USD amount overflows fixed-point storage")
	}
	f, err := strconv.ParseInt(fraction+strings.Repeat("0", 9-len(fraction)), 10, 64)
	if err != nil {
		return 0, err
	}
	value := whole * int64(Dollar)
	if value > math.MaxInt64-f {
		return 0, fmt.Errorf("USD amount overflows fixed-point storage")
	}
	return Money(value + f), nil
}

// ParseCharge rounds a nonnegative provider decimal upward to the next
// billionth of USD. The original provider usage remains in receipt evidence.
func ParseCharge(s string) (Money, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 || len(parts[1]) <= 9 {
		return ParseMoney(s)
	}
	for _, part := range parts {
		if part == "" {
			return 0, fmt.Errorf("invalid USD charge")
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("invalid USD charge")
			}
		}
	}
	value, err := ParseMoney(parts[0] + "." + parts[1][:9])
	if err != nil {
		return 0, err
	}
	for _, digit := range parts[1][9:] {
		if digit != '0' {
			rounded, err := add64(int64(value), 1)
			return Money(rounded), err
		}
	}
	return value, nil
}

func (m Money) String() string {
	n := int64(m)
	sign := ""
	if n < 0 {
		sign = "-"
	} // Handle MinInt64 without negating it.
	var magnitude uint64
	if n < 0 {
		magnitude = uint64(-(n + 1)) + 1
	} else {
		magnitude = uint64(n)
	}
	return fmt.Sprintf("%s%d.%09d", sign, magnitude/uint64(Dollar), magnitude%uint64(Dollar))
}
func (m Money) MarshalJSON() ([]byte, error) { return json.Marshal(m.String()) }
func (m *Money) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("USD amount must be a JSON decimal string")
	}
	negative := strings.HasPrefix(s, "-")
	value, err := ParseMoney(strings.TrimPrefix(s, "-"))
	if err != nil {
		if s == "-9223372036.854775808" {
			*m = Money(math.MinInt64)
			return nil
		}
		return err
	}
	if negative {
		value = -value
	}
	*m = value
	return nil
}
func add64(a, b int64) (int64, error) {
	if b > 0 && a > math.MaxInt64-b || b < 0 && a < math.MinInt64-b {
		return 0, fmt.Errorf("budget accounting overflow")
	}
	return a + b, nil
}

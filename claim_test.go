package claims

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestShouldCreateClaimWhenGivenKeyAndValue(t *testing.T) {
	// Arrange
	key := "test_key"
	value := "test_value"

	// Act
	claim := NewClaim(key, value)

	// Assert
	assert.Equal(t, key, claim.Name())
	assert.Equal(t, value, claim.Value())
}

func TestShouldSplitValuesWhenGivenSeparator(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		separator string
		expected  []string
	}{
		{
			name:      "should split comma-separated values",
			value:     "read,write,admin",
			separator: ",",
			expected:  []string{"read", "write", "admin"},
		},
		{
			name:      "should split space-separated values",
			value:     "user admin guest",
			separator: " ",
			expected:  []string{"user", "admin", "guest"},
		},
		{
			name:      "should return single value when no separator found",
			value:     "single_value",
			separator: ",",
			expected:  []string{"single_value"},
		},
		{
			name:      "should handle empty value",
			value:     "",
			separator: ",",
			expected:  []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			claim := NewClaim("test", tt.value)

			// Act
			result := claim.Values(tt.separator)

			// Assert
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldParseIntValueWhenGivenValidString(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expectedInt   int
		expectedValid bool
	}{
		{
			name:          "should parse valid positive integer",
			value:         "12345",
			expectedInt:   12345,
			expectedValid: true,
		},
		{
			name:          "should parse valid negative integer",
			value:         "-678",
			expectedInt:   -678,
			expectedValid: true,
		},
		{
			name:          "should parse zero",
			value:         "0",
			expectedInt:   0,
			expectedValid: true,
		},
		{
			name:          "should return false for non-integer string",
			value:         "not_a_number",
			expectedInt:   0,
			expectedValid: false,
		},
		{
			name:          "should return false for float string",
			value:         "123.45",
			expectedInt:   0,
			expectedValid: false,
		},
		{
			name:          "should return false for empty string",
			value:         "",
			expectedInt:   0,
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			claim := NewClaim("test", tt.value)

			// Act
			result, valid := claim.IntValue()

			// Assert
			assert.Equal(t, tt.expectedInt, result)
			assert.Equal(t, tt.expectedValid, valid)
		})
	}
}

func TestShouldParseInt32ValueWhenGivenValidString(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expectedInt32 int32
		expectedValid bool
	}{
		{
			name:          "should parse valid int32",
			value:         "2147483647",
			expectedInt32: 2147483647,
			expectedValid: true,
		},
		{
			name:          "should parse negative int32",
			value:         "-2147483648",
			expectedInt32: -2147483648,
			expectedValid: true,
		},
		{
			name:          "should return false for invalid string",
			value:         "invalid",
			expectedInt32: 0,
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			claim := NewClaim("test", tt.value)

			// Act
			result, valid := claim.Int32Value()

			// Assert
			assert.Equal(t, tt.expectedInt32, result)
			assert.Equal(t, tt.expectedValid, valid)
		})
	}
}

func TestShouldParseInt64ValueWhenGivenValidString(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expectedInt64 int64
		expectedValid bool
	}{
		{
			name:          "should parse valid int64",
			value:         "9223372036854775807",
			expectedInt64: 9223372036854775807,
			expectedValid: true,
		},
		{
			name:          "should parse negative int64",
			value:         "-9223372036854775808",
			expectedInt64: -9223372036854775808,
			expectedValid: true,
		},
		{
			name:          "should return false for invalid string",
			value:         "invalid",
			expectedInt64: 0,
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			claim := NewClaim("test", tt.value)

			// Act
			result, valid := claim.Int64Value()

			// Assert
			assert.Equal(t, tt.expectedInt64, result)
			assert.Equal(t, tt.expectedValid, valid)
		})
	}
}

func TestShouldParseFloat64ValueWhenGivenValidString(t *testing.T) {
	tests := []struct {
		name            string
		value           string
		expectedFloat64 float64
		expectedValid   bool
	}{
		{
			name:            "should parse valid float",
			value:           "123.456",
			expectedFloat64: 123.456,
			expectedValid:   true,
		},
		{
			name:            "should parse integer as float",
			value:           "789",
			expectedFloat64: 789.0,
			expectedValid:   true,
		},
		{
			name:            "should parse negative float",
			value:           "-456.789",
			expectedFloat64: -456.789,
			expectedValid:   true,
		},
		{
			name:            "should return false for invalid string",
			value:           "not_a_number",
			expectedFloat64: 0,
			expectedValid:   false,
		},
		{
			name:            "should return false for empty string",
			value:           "",
			expectedFloat64: 0,
			expectedValid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			claim := NewClaim("test", tt.value)

			// Act
			result, valid := claim.Float64Value()

			// Assert
			assert.Equal(t, tt.expectedFloat64, result)
			assert.Equal(t, tt.expectedValid, valid)
		})
	}
}

func TestShouldReturnZeroWhenClaimIsNil(t *testing.T) {
	// Arrange
	var claim *claim

	// Act
	result, valid := claim.Float64Value()

	// Assert
	assert.Equal(t, float64(0), result)
	assert.False(t, valid)
}

func TestShouldParseBoolValueWhenGivenValidString(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		expectedBool bool
		expectedValid bool
	}{
		{
			name:         "should parse true",
			value:        "true",
			expectedBool: true,
			expectedValid: true,
		},
		{
			name:         "should parse false",
			value:        "false",
			expectedBool: false,
			expectedValid: true,
		},
		{
			name:         "should parse 1 as true",
			value:        "1",
			expectedBool: true,
			expectedValid: true,
		},
		{
			name:         "should parse 0 as false",
			value:        "0",
			expectedBool: false,
			expectedValid: true,
		},
		{
			name:         "should return false for invalid string",
			value:        "invalid",
			expectedBool: false,
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			claim := NewClaim("test", tt.value)

			// Act
			result, valid := claim.BoolValue()

			// Assert
			assert.Equal(t, tt.expectedBool, result)
			assert.Equal(t, tt.expectedValid, valid)
		})
	}
}

func TestShouldParseUUIDValueWhenGivenValidString(t *testing.T) {
	// Arrange
	validUUIDStr := "123e4567-e89b-12d3-a456-426614174000"
	validUUID := uuid.MustParse(validUUIDStr)

	tests := []struct {
		name         string
		value        string
		expectedUUID uuid.UUID
		expectedValid bool
	}{
		{
			name:         "should parse valid UUID",
			value:        validUUIDStr,
			expectedUUID: validUUID,
			expectedValid: true,
		},
		{
			name:         "should return false for invalid UUID",
			value:        "invalid-uuid",
			expectedUUID: uuid.UUID{},
			expectedValid: false,
		},
		{
			name:         "should return false for empty string",
			value:        "",
			expectedUUID: uuid.UUID{},
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			claim := NewClaim("test", tt.value)

			// Act
			result, valid := claim.UUIDValue()

			// Assert
			assert.Equal(t, tt.expectedUUID, result)
			assert.Equal(t, tt.expectedValid, valid)
		})
	}
}

func TestShouldReturnErrorWhenMarshalingToJSON(t *testing.T) {
	// Arrange
	claim := NewClaim("test", "value").(*claim)

	// Act
	result, err := claim.MarshalJSON()

	// Assert
	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ClaimSet should not be marshaled to JSON")
}

func TestShouldReturnErrorWhenUnmarshalingFromJSON(t *testing.T) {
	// Arrange
	claim := NewClaim("test", "value").(*claim)
	jsonData := []byte(`{"test": "value"}`)

	// Act
	err := claim.UnmarshalJSON(jsonData)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ClaimSet should not be unmarshaled from JSON")
}
package util

import (
	"strings"
)

// EncodeToQueryString encodes a map of strings to a single string where keys and values are separated by teh keyValueSeparator
//  and key-value pairs are separated by the groupSeparator. The keys must be specified to encode in the proper order
func EncodeToQueryString(inputs map[string]string, keys []string, keyValueSeparator string, groupSeparator string) string {
	keyValuePairs := make([]string, len(inputs))
	for i, key := range keys {
		keyValuePairs[i] = key + keyValueSeparator + inputs[key]
		i++
	}
	return strings.Join(keyValuePairs, groupSeparator)
}

// DecodeQueryString parse a string encoding of key value pairs where keys and values are separated by the keyValueSeparator
//  and key-value pairs are separated by the groupSeparator
func DecodeQueryString(input string, keyValueSparator string, groupSeparator string) map[string]string {
	dict := make(map[string]string)
	keyvaluepairs := strings.Split(input, groupSeparator)
	for _, pair := range keyvaluepairs {
		keyandvalue := strings.Split(pair, keyValueSparator)
		var value string
		// if the length > 2 then there is an "=" in the value so we should rejoin
		//  it to make the value whole again

		switch {
		case len(keyandvalue) > 2:
			value = strings.Join(keyandvalue[1:], keyValueSparator)
		case len(keyandvalue) == 2:
			value = keyandvalue[1]
		default:
			continue
		}
		key := keyandvalue[0]
		dict[key] = value
	}
	return dict
}

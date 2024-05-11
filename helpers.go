package anonymizer

import (
	"strings"
	"unsafe"

	"github.com/brianvoe/gofakeit/v6"
)

// Used for parsing the tag in a struct
func parseNameAndParamsFromTag(tag string) (string, string) {
	// Trim the curly on the beginning and end
	tag = strings.TrimLeft(tag, "{")
	tag = strings.TrimRight(tag, "}")
	// Check if it has params separated by :
	fNameSplit := strings.SplitN(tag, ":", 2)
	fName := ""
	fParams := ""
	if len(fNameSplit) >= 1 {
		fName = fNameSplit[0]
	}
	if len(fNameSplit) >= 2 {
		fParams = fNameSplit[1]
	}
	return fName, fParams
}

func funcLookupSplit(str string) []string {
	var out []string
	for str != "" {
		if strings.HasPrefix(str, "[") {
			startIndex := strings.Index(str, "[")
			endIndex := strings.Index(str, "]")
			val := str[(startIndex) : endIndex+1]
			out = append(out, strings.TrimSpace(val))
			str = strings.Replace(str, val, "", 1)

			// Trim off comma if it has it
			if strings.HasPrefix(str, ",") {
				str = strings.Replace(str, ",", "", 1)
			}
		} else {
			strSplit := strings.SplitN(str, ",", 2)
			strSplitLen := len(strSplit)
			if strSplitLen >= 1 {
				out = append(out, strings.TrimSpace(strSplit[0]))
			}
			if strSplitLen >= 2 {
				str = strSplit[1]
			} else {
				str = ""
			}
		}
	}

	return out
}

// Used for parsing map params
func parseMapParams(info *gofakeit.Info, fParams string) *gofakeit.MapParams {
	// Get parameters, make sure params and the split both have values
	mapParams := gofakeit.NewMapParams()
	paramsLen := len(info.Params)

	// If just one param and it's a string simply just pass it
	if paramsLen == 1 && info.Params[0].Type == "string" {
		mapParams.Add(info.Params[0].Field, fParams)
	} else if paramsLen > 0 && fParams != "" {
		splitVals := funcLookupSplit(fParams)
		mapParams = addSplitValsToMapParams(splitVals, info, mapParams)
	}
	if mapParams.Size() > 0 {
		return mapParams
	} else {
		return nil
	}
}

// Used for splitting the values
func addSplitValsToMapParams(splitVals []string, info *gofakeit.Info, mapParams *gofakeit.MapParams) *gofakeit.MapParams {
	for ii := 0; ii < len(splitVals); ii++ {
		if len(info.Params)-1 >= ii {
			if strings.HasPrefix(splitVals[ii], "[") {
				lookupSplits := funcLookupSplit(strings.TrimRight(strings.TrimLeft(splitVals[ii], "["), "]"))
				for _, v := range lookupSplits {
					mapParams.Add(info.Params[ii].Field, v)
				}
			} else {
				mapParams.Add(info.Params[ii].Field, splitVals[ii])
			}
		}
	}
	return mapParams
}

// s2b converts a string to a byte slice without memory allocation.
// NOTE: The returned byte slice MUST NOT be modified since it shares the same backing array
// with the given string.
func s2b(s string) []byte {
	p := unsafe.StringData(s)
	b := unsafe.Slice(p, len(s))
	return b
}

// b2s converts bytes to a string without memory allocation.
// NOTE: The given bytes MUST NOT be modified since they share the same backing array
// with the returned string.
func b2s(b []byte) string {
	// Ignore if your IDE shows an error here; it's a false positive.
	p := unsafe.SliceData(b)
	return unsafe.String(p, len(b))
}

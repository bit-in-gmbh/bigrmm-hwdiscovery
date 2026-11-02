//go:build linux && (amd64 || arm64)

package hwdiscovery

import (
	"encoding/binary"
	"path/filepath"
	"strconv"
	"strings"
)

type dmiRecord struct {
	formatted []byte
	strings   []string
}

func readDMIRecords(source linuxSource, recordType uint8) []dmiRecord {
	root := source.sys("firmware", "dmi", "entries")
	records := make([]dmiRecord, 0)
	for _, name := range sortedDirNames(root) {
		typeValue, _, found := strings.Cut(name, "-")
		if !found || typeValue != strconv.Itoa(int(recordType)) {
			continue
		}
		raw, err := readLinuxFile(filepath.Join(root, name, "raw"), maxLinuxAttributeBytes)
		if err != nil {
			continue
		}
		if record, ok := parseDMIRecord(raw, recordType); ok {
			records = append(records, record)
		}
	}
	return records
}

func parseDMIRecord(raw []byte, recordType uint8) (dmiRecord, bool) {
	if len(raw) < 4 || raw[0] != recordType {
		return dmiRecord{}, false
	}
	formattedLength := int(raw[1])
	if formattedLength < 4 || formattedLength > len(raw) {
		return dmiRecord{}, false
	}
	record := dmiRecord{formatted: raw[:formattedLength]}
	stringsData := raw[formattedLength:]
	for len(stringsData) > 0 && stringsData[0] != 0 {
		end := 0
		for end < len(stringsData) && stringsData[end] != 0 {
			end++
		}
		if end == len(stringsData) {
			return dmiRecord{}, false
		}
		record.strings = append(record.strings, cleanLinuxString(string(stringsData[:end])))
		stringsData = stringsData[end+1:]
	}
	return record, true
}

func (r dmiRecord) stringAt(offset int) string {
	if offset < 0 || offset >= len(r.formatted) {
		return ""
	}
	index := int(r.formatted[offset])
	if index == 0 || index > len(r.strings) {
		return ""
	}
	return r.strings[index-1]
}

func (r dmiRecord) uint16At(offset int) uint16 {
	if offset < 0 || offset+2 > len(r.formatted) {
		return 0
	}
	return binary.LittleEndian.Uint16(r.formatted[offset : offset+2])
}

func (r dmiRecord) uint32At(offset int) uint32 {
	if offset < 0 || offset+4 > len(r.formatted) {
		return 0
	}
	return binary.LittleEndian.Uint32(r.formatted[offset : offset+4])
}

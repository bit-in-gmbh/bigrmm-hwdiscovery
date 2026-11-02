//go:build windows && (amd64 || arm64)

package hwdiscovery

import "strings"

func normalizeSystemType(value string) string {
	value = strings.ToLower(cleanString(value))
	switch {
	case strings.Contains(value, "arm64") || strings.Contains(value, "aarch64"):
		return "arm64"
	case strings.Contains(value, "arm"):
		return "arm"
	case strings.Contains(value, "x64") || strings.Contains(value, "x86-64") || strings.Contains(value, "amd64"):
		return "x86_64"
	case strings.Contains(value, "x86") || strings.Contains(value, "i386") || strings.Contains(value, "i686"):
		return "x86"
	default:
		return ""
	}
}

func normalizeProcessorArchitecture(value *uint16) string {
	if value == nil {
		return ""
	}
	switch *value {
	case 0:
		return "x86"
	case 1:
		return "mips"
	case 2:
		return "alpha"
	case 3:
		return "powerpc"
	case 5:
		return "arm"
	case 6:
		return "ia64"
	case 9:
		return "x86_64"
	case 12:
		return "arm64"
	default:
		return ""
	}
}

func normalizeChassisType(values []int32) string {
	for _, value := range values {
		if value >= 0 && value <= 0xffff {
			if normalized := chassisType(uint16(value)); normalized != "" {
				return normalized
			}
		}
	}
	return ""
}

func normalizeMemoryType(smbios *uint32, legacy *uint16) string {
	if smbios != nil {
		if normalized := smbiosMemoryType(*smbios); normalized != "" {
			return normalized
		}
	}
	if legacy == nil {
		return ""
	}
	legacyTypes := map[uint16]string{
		1: "other", 2: "dram", 3: "synchronous_dram", 4: "cache_dram", 5: "edo",
		6: "edram", 7: "vram", 8: "sram", 9: "ram", 10: "rom", 11: "flash",
		12: "eeprom", 13: "feprom", 14: "eprom", 15: "cdram", 16: "3dram",
		17: "sdram", 18: "sgram", 19: "rdram", 20: "ddr", 21: "ddr2",
		22: "ddr2_fb_dimm", 24: "ddr3", 26: "ddr4",
	}
	return legacyTypes[*legacy]
}

func normalizeMemoryFormFactor(value *uint16) string {
	if value == nil {
		return ""
	}
	return memoryFormFactor(*value)
}

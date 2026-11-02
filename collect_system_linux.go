//go:build linux && (amd64 || arm64)

package hwdiscovery

import (
	"runtime"
	"strconv"
	"time"
)

func collectLinuxSystem(source linuxSource) *System {
	dmi := source.sys("class", "dmi", "id")
	system := System{
		Manufacturer: readClean(dmi + "/sys_vendor"),
		Model:        readClean(dmi + "/product_name"),
		Family:       readClean(dmi + "/product_family"),
		Version:      readClean(dmi + "/product_version"),
		SerialNumber: readClean(dmi + "/product_serial"),
		UUID:         normalizeUUID(readClean(dmi + "/product_uuid")),
		SKU:          readClean(dmi + "/product_sku"),
		SystemType:   linuxArchitecture(runtime.GOARCH),
	}

	chassis := Chassis{
		Manufacturer: readClean(dmi + "/chassis_vendor"),
		Model:        readClean(dmi + "/chassis_version"),
		SerialNumber: readClean(dmi + "/chassis_serial"),
		AssetTag:     readClean(dmi + "/chassis_asset_tag"),
	}
	if value, ok := readUint(dmi+"/chassis_type", 16); ok {
		chassis.Type = chassisType(uint16(value))
	}
	if chassis != (Chassis{}) {
		system.Chassis = &chassis
	}

	baseboard := Baseboard{
		Manufacturer: readClean(dmi + "/board_vendor"),
		Product:      readClean(dmi + "/board_name"),
		Version:      readClean(dmi + "/board_version"),
		SerialNumber: readClean(dmi + "/board_serial"),
	}
	if baseboard != (Baseboard{}) {
		system.Baseboard = &baseboard
	}

	firmware := Firmware{
		Vendor:      readClean(dmi + "/bios_vendor"),
		Version:     readClean(dmi + "/bios_version"),
		ReleaseDate: normalizeLinuxFirmwareDate(readClean(dmi + "/bios_date")),
	}
	if firmware != (Firmware{}) {
		system.Firmware = &firmware
	}

	deviceTree := source.sys("firmware", "devicetree", "base")
	model := firstNULFile(deviceTree + "/model")
	compatible := firstNULFile(deviceTree + "/compatible")
	serial := firstNULFile(deviceTree + "/serial-number")
	system.Model = firstString(system.Model, model)
	system.Family = firstString(system.Family, compatible)
	system.SerialNumber = firstString(system.SerialNumber, serial)
	if system.Manufacturer == "" {
		if vendor, _, found := cutCompatible(compatible); found {
			system.Manufacturer = vendor
		}
	}

	if system == (System{}) {
		return nil
	}
	return &system
}

func linuxArchitecture(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "arm64"
	default:
		return ""
	}
}

func normalizeLinuxFirmwareDate(value string) string {
	for _, layout := range []string{"01/02/2006", "01/02/06", "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.Format("2006-01-02")
		}
	}
	return ""
}

func firstNULFile(path string) string {
	data, err := readLinuxFile(path, maxLinuxAttributeBytes)
	if err != nil {
		return ""
	}
	return firstNULString(data)
}

func cutCompatible(value string) (string, string, bool) {
	for index := 0; index < len(value); index++ {
		if value[index] == ',' {
			return cleanString(value[:index]), cleanString(value[index+1:]), true
		}
	}
	return "", "", false
}

func parsePositiveInt(value string) (int, bool) {
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil && parsed >= 0
}

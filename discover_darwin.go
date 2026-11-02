//go:build darwin

package hwdiscovery

import (
	"math"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type darwinRecord map[string]string

type darwinNativeInventory struct {
	system  darwinRecord
	storage []darwinRecord
	network []darwinRecord
	gpus    []darwinRecord
	smbios  []byte
}

type darwinSysctlValues struct {
	strings map[string]string
	uints   map[string]uint64
}

// Discover returns a best-effort inventory of static hardware identity and
// configuration exposed by Darwin sysctls and native Apple frameworks.
// Inaccessible or unavailable properties are omitted.
func Discover() Inventory {
	return discoverDarwin(readDarwinSysctls(), readDarwinNativeInventory())
}

func discoverDarwin(sysctls darwinSysctlValues, native darwinNativeInventory) Inventory {
	return Inventory{
		System:          collectDarwinSystem(sysctls, native.system),
		Memory:          collectDarwinMemory(sysctls, native.smbios),
		Processors:      collectDarwinProcessors(sysctls),
		Disks:           collectDarwinDisks(native.storage),
		NetworkAdapters: collectDarwinNetworkAdapters(native.network),
		GPUs:            collectDarwinGPUs(native.gpus),
	}
}

func readDarwinSysctls() darwinSysctlValues {
	values := darwinSysctlValues{
		strings: make(map[string]string),
		uints:   make(map[string]uint64),
	}
	for _, name := range []string{
		"hw.model",
		"machdep.cpu.brand_string",
		"machdep.cpu.vendor",
	} {
		if value, err := unix.Sysctl(name); err == nil {
			if value = cleanString(value); value != "" {
				values.strings[name] = value
			}
		}
	}
	for _, name := range []string{
		"hw.memsize",
		"hw.packages",
		"hw.physicalcpu",
		"hw.logicalcpu",
		"hw.cpufrequency_max",
	} {
		if value, ok := darwinSysctlUint(name); ok {
			values.uints[name] = value
		}
	}
	return values
}

func darwinSysctlUint(name string) (uint64, bool) {
	if value, err := unix.SysctlUint64(name); err == nil {
		return value, true
	}
	if value, err := unix.SysctlUint32(name); err == nil {
		return uint64(value), true
	}
	return 0, false
}

func collectDarwinSystem(sysctls darwinSysctlValues, native darwinRecord) *System {
	model := firstString(cleanString(native["model"]), cleanString(sysctls.strings["hw.model"]))
	manufacturer := cleanString(native["manufacturer"])
	if manufacturer == "" && looksLikeAppleModel(model) {
		manufacturer = "Apple Inc."
	}
	system := System{
		Manufacturer: manufacturer,
		Model:        model,
		Family:       cleanString(native["product_name"]),
		Version:      cleanString(native["model_number"]),
		SerialNumber: cleanString(native["serial_number"]),
		UUID:         normalizeUUID(native["uuid"]),
		SKU:          cleanString(native["target_type"]),
		SystemType:   darwinArchitecture(runtime.GOARCH),
	}

	chassis := Chassis{
		Manufacturer: cleanString(native["chassis_manufacturer"]),
		Model:        cleanString(native["chassis_model"]),
		SerialNumber: cleanString(native["chassis_serial"]),
		AssetTag:     cleanString(native["asset_tag"]),
		Type:         normalizeDarwinChassisType(firstString(native["chassis_type"], system.Family, system.Model)),
	}
	if chassis.Manufacturer == "" && chassis.Type != "" {
		chassis.Manufacturer = system.Manufacturer
	}
	if chassis != (Chassis{}) {
		system.Chassis = &chassis
	}

	baseboard := Baseboard{
		Manufacturer: firstString(cleanString(native["board_manufacturer"]), manufacturer),
		Product:      cleanString(native["board_id"]),
		Version:      cleanString(native["board_version"]),
		SerialNumber: cleanString(native["board_serial"]),
	}
	if baseboard.Product == "" && baseboard.Version == "" && baseboard.SerialNumber == "" {
		baseboard.Manufacturer = ""
	}
	if baseboard != (Baseboard{}) {
		system.Baseboard = &baseboard
	}

	firmware := Firmware{
		Vendor:      cleanString(native["firmware_vendor"]),
		Version:     cleanString(native["firmware_version"]),
		ReleaseDate: normalizeDarwinFirmwareDate(native["firmware_date"]),
	}
	if firmware.Vendor == "" && (firmware.Version != "" || firmware.ReleaseDate != "") {
		firmware.Vendor = manufacturer
	}
	if firmware != (Firmware{}) {
		system.Firmware = &firmware
	}

	if system == (System{}) {
		return nil
	}
	return &system
}

func looksLikeAppleModel(value string) bool {
	value = strings.ToLower(value)
	for _, prefix := range []string{"mac", "imac", "xserve"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func darwinArchitecture(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "arm64"
	default:
		return ""
	}
}

func normalizeDarwinChassisType(value string) string {
	normalized := strings.ToLower(cleanString(value))
	switch {
	case strings.Contains(normalized, "macbook"):
		return "notebook"
	case strings.Contains(normalized, "imac"):
		return "all_in_one"
	case strings.Contains(normalized, "mac mini") || strings.Contains(normalized, "macmini"):
		return "mini_pc"
	case strings.Contains(normalized, "mac studio") || strings.Contains(normalized, "macstudio"):
		return "desktop"
	case strings.Contains(normalized, "mac pro") || strings.Contains(normalized, "macpro"):
		return "desktop"
	case strings.Contains(normalized, "xserve"):
		return "rack_mount_chassis"
	default:
		return ""
	}
}

func normalizeDarwinFirmwareDate(value string) string {
	value = cleanString(value)
	for _, layout := range []string{"2006-01-02", "01/02/2006", "01/02/06", "20060102"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.Format("2006-01-02")
		}
	}
	return ""
}

func collectDarwinProcessors(sysctls darwinSysctlValues) []Processor {
	physical := sysctls.uints["hw.physicalcpu"]
	logical := sysctls.uints["hw.logicalcpu"]
	packages := sysctls.uints["hw.packages"]
	if packages == 0 && (physical != 0 || logical != 0 || sysctls.strings["machdep.cpu.brand_string"] != "") {
		packages = 1
	}
	// A corrupt sysctl must not control an unbounded slice allocation. This is
	// deliberately far above the package count of supported Mac hardware.
	if packages == 0 || packages > 1024 || (physical != 0 && packages > physical) ||
		(logical != 0 && packages > logical) {
		return nil
	}

	model := cleanString(sysctls.strings["machdep.cpu.brand_string"])
	manufacturer := cleanString(sysctls.strings["machdep.cpu.vendor"])
	if manufacturer == "GenuineIntel" {
		manufacturer = "Intel"
	} else if manufacturer == "AuthenticAMD" {
		manufacturer = "AMD"
	} else if manufacturer == "" && strings.HasPrefix(strings.ToLower(model), "apple ") {
		manufacturer = "Apple Inc."
	}
	frequency := sysctls.uints["hw.cpufrequency_max"]
	maxMHz := uint32(0)
	if frequency/1_000_000 <= math.MaxUint32 {
		maxMHz = uint32(frequency / 1_000_000)
	}

	processors := make([]Processor, 0, packages)
	for index := uint64(0); index < packages; index++ {
		processor := Processor{
			ID:           "CPU" + strconv.FormatUint(index, 10),
			Manufacturer: manufacturer,
			Model:        model,
			Architecture: darwinArchitecture(runtime.GOARCH),
			MaxClockMHz:  maxMHz,
		}
		processor.PhysicalCoreCount = dividedCount(physical, packages, index)
		processor.LogicalProcessorCount = dividedCount(logical, packages, index)
		processors = append(processors, processor)
	}
	return processors
}

func dividedCount(total, parts, index uint64) uint32 {
	if total == 0 || parts == 0 || total > math.MaxUint32 {
		return 0
	}
	value := total / parts
	if index < total%parts {
		value++
	}
	return uint32(value)
}

func collectDarwinMemory(sysctls darwinSysctlValues, smbios []byte) *Memory {
	modules := parseDarwinSMBIOSMemory(smbios)
	installed := sysctls.uints["hw.memsize"]
	if installed == 0 {
		for _, module := range modules {
			if math.MaxUint64-installed < module.CapacityBytes {
				installed = 0
				break
			}
			installed += module.CapacityBytes
		}
	}
	if installed == 0 && len(modules) == 0 {
		return nil
	}
	return &Memory{InstalledPhysicalBytes: installed, Modules: modules}
}

func collectDarwinDisks(records []darwinRecord) []Disk {
	disks := make([]Disk, 0)
	diskByID := make(map[string]int)
	partitionByID := make(map[string]struct{ disk, partition int })

	for _, record := range records {
		if record["kind"] != "disk" {
			continue
		}
		id := darwinDeviceID(record["id"])
		if id == "" {
			continue
		}
		disk := Disk{
			ID:                      id,
			Index:                   parseUint32Ptr(record["index"]),
			PNPID:                   cleanString(record["pnp_id"]),
			Vendor:                  cleanString(record["vendor"]),
			Model:                   cleanString(record["model"]),
			SerialNumber:            cleanString(record["serial_number"]),
			CapacityBytes:           parseUint64(record["capacity_bytes"]),
			LogicalSectorSizeBytes:  parseUint32(record["logical_sector_size_bytes"]),
			PhysicalSectorSizeBytes: parseUint32(record["physical_sector_size_bytes"]),
			MediaType:               normalizeDarwinMediaType(record["media_type"]),
			BusType:                 normalizeDarwinBusType(record["bus_type"]),
			PartitionTableType:      normalizeDarwinPartitionTable(record["partition_table_type"]),
		}
		if disk.Vendor == "" && strings.HasPrefix(strings.ToLower(disk.Model), "apple ") {
			disk.Vendor = "Apple Inc."
		}
		diskByID[id] = len(disks)
		disks = append(disks, disk)
	}

	for _, record := range records {
		if record["kind"] != "partition" {
			continue
		}
		parent := darwinDeviceID(record["parent"])
		diskIndex, ok := diskByID[parent]
		if !ok {
			continue
		}
		id := darwinDeviceID(record["id"])
		if id == "" {
			continue
		}
		partition := Partition{
			ID:                  id,
			Index:               parseUint32Ptr(record["index"]),
			SizeBytes:           parseUint64(record["size_bytes"]),
			StartingOffsetBytes: parseUint64(record["starting_offset_bytes"]),
		}
		partitionByID[id] = struct{ disk, partition int }{diskIndex, len(disks[diskIndex].Partitions)}
		disks[diskIndex].Partitions = append(disks[diskIndex].Partitions, partition)
	}

	for _, record := range records {
		if record["kind"] != "volume" {
			continue
		}
		location, ok := partitionByID[darwinDeviceID(record["parent"])]
		if !ok {
			continue
		}
		volume := Volume{
			ID:            firstString(cleanString(record["id"]), darwinDeviceID(record["parent"])),
			Label:         cleanString(record["label"]),
			Filesystem:    normalizeDarwinFilesystem(record["filesystem"]),
			CapacityBytes: parseUint64(record["capacity_bytes"]),
		}
		if mount := cleanString(record["mount_point"]); mount != "" {
			volume.MountPoints = []string{mount}
		}
		if volume.ID == "" && volume.Label == "" && volume.Filesystem == "" && volume.CapacityBytes == 0 && len(volume.MountPoints) == 0 {
			continue
		}
		partition := &disks[location.disk].Partitions[location.partition]
		partition.Volumes = append(partition.Volumes, volume)
	}

	for diskIndex := range disks {
		sort.Slice(disks[diskIndex].Partitions, func(i, j int) bool {
			left, right := disks[diskIndex].Partitions[i], disks[diskIndex].Partitions[j]
			if left.Index != nil && right.Index != nil && *left.Index != *right.Index {
				return *left.Index < *right.Index
			}
			return left.ID < right.ID
		})
		for partitionIndex := range disks[diskIndex].Partitions {
			volumes := mergeAndSortDarwinVolumes(disks[diskIndex].Partitions[partitionIndex].Volumes)
			for volumeIndex := range volumes {
				sort.Strings(volumes[volumeIndex].MountPoints)
			}
			disks[diskIndex].Partitions[partitionIndex].Volumes = volumes
		}
	}
	sort.Slice(disks, func(i, j int) bool {
		if disks[i].Index != nil && disks[j].Index != nil && *disks[i].Index != *disks[j].Index {
			return *disks[i].Index < *disks[j].Index
		}
		return disks[i].ID < disks[j].ID
	})
	return disks
}

func mergeAndSortDarwinVolumes(volumes []Volume) []Volume {
	byKey := make(map[string]Volume)
	for _, volume := range volumes {
		key := volume.ID
		if key == "" || strings.HasPrefix(key, "/dev/") {
			key += "\x00" + volume.Label + "\x00" + volume.Filesystem + "\x00" + strconv.FormatUint(volume.CapacityBytes, 10)
		}
		if existing, ok := byKey[key]; ok {
			existing.Label = firstString(existing.Label, volume.Label)
			existing.Filesystem = firstString(existing.Filesystem, volume.Filesystem)
			if existing.CapacityBytes == 0 {
				existing.CapacityBytes = volume.CapacityBytes
			}
			existing.MountPoints = append(existing.MountPoints, volume.MountPoints...)
			existing.MountPoints = uniqueSortedStrings(existing.MountPoints)
			byKey[key] = existing
			continue
		}
		volume.MountPoints = uniqueSortedStrings(volume.MountPoints)
		byKey[key] = volume
	}
	result := make([]Volume, 0, len(byKey))
	for _, volume := range byKey {
		result = append(result, volume)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		if left.Label != right.Label {
			return left.Label < right.Label
		}
		if left.Filesystem != right.Filesystem {
			return left.Filesystem < right.Filesystem
		}
		if left.CapacityBytes != right.CapacityBytes {
			return left.CapacityBytes < right.CapacityBytes
		}
		return strings.Join(left.MountPoints, "\x00") < strings.Join(right.MountPoints, "\x00")
	})
	return result
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return result
}

func darwinDeviceID(value string) string {
	value = cleanString(value)
	if value == "" || strings.HasPrefix(value, "/dev/") {
		return value
	}
	return "/dev/" + value
}

func parseUint64(value string) uint64 {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 0, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func parseUint32(value string) uint32 {
	parsed := parseUint64(value)
	if parsed > math.MaxUint32 {
		return 0
	}
	return uint32(parsed)
}

func parseUint32Ptr(value string) *uint32 {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 0, 32)
	if err != nil {
		return nil
	}
	result := uint32(parsed)
	return &result
}

func normalizeDarwinMediaType(value string) string {
	normalized := strings.ToLower(cleanString(value))
	switch {
	case strings.Contains(normalized, "solid"), strings.Contains(normalized, "ssd"), strings.Contains(normalized, "flash"):
		return "ssd"
	case strings.Contains(normalized, "rotational"), strings.Contains(normalized, "hard disk"), strings.Contains(normalized, "hdd"):
		return "hdd"
	case strings.Contains(normalized, "optical"), strings.Contains(normalized, "cd"), strings.Contains(normalized, "dvd"):
		return "optical"
	default:
		return normalizeDarwinEnum(normalized)
	}
}

func normalizeDarwinBusType(value string) string {
	normalized := strings.ToLower(cleanString(value))
	for _, bus := range []struct {
		match string
		value string
	}{
		{"nvme", "nvme"}, {"non-volatile memory", "nvme"}, {"thunderbolt", "thunderbolt"},
		{"usb", "usb"}, {"serial ata", "sata"}, {"sata", "sata"}, {"ata", "ata"},
		{"sas", "sas"}, {"scsi", "scsi"}, {"firewire", "firewire"}, {"sd", "sd"},
		{"pci", "pci"},
	} {
		if strings.Contains(normalized, bus.match) {
			return bus.value
		}
	}
	return normalizeDarwinEnum(normalized)
}

func normalizeDarwinPartitionTable(value string) string {
	normalized := strings.ToLower(cleanString(value))
	switch {
	case strings.Contains(normalized, "guid"), strings.Contains(normalized, "gpt"):
		return "gpt"
	case strings.Contains(normalized, "fdisk"), strings.Contains(normalized, "master boot"), strings.Contains(normalized, "mbr"):
		return "mbr"
	case strings.Contains(normalized, "apple_partition"), strings.Contains(normalized, "apple partition"):
		return "apm"
	default:
		return normalizeDarwinEnum(normalized)
	}
}

func normalizeDarwinFilesystem(value string) string {
	normalized := strings.ToLower(cleanString(value))
	switch normalized {
	case "apfs":
		return "apfs"
	case "hfs", "hfs+", "hfsplus":
		return "hfs_plus"
	case "msdos", "msdosfs", "fat", "fat32":
		return "fat32"
	case "exfat":
		return "exfat"
	case "ntfs":
		return "ntfs"
	default:
		return normalizeDarwinEnum(normalized)
	}
}

func normalizeDarwinEnum(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var result strings.Builder
	underscore := false
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			result.WriteRune(character)
			underscore = false
		} else if result.Len() > 0 && !underscore {
			result.WriteByte('_')
			underscore = true
		}
	}
	return strings.Trim(result.String(), "_")
}

func collectDarwinNetworkAdapters(records []darwinRecord) []NetworkAdapter {
	byID := make(map[string]NetworkAdapter)
	for _, record := range records {
		if record["kind"] != "network" {
			continue
		}
		id := cleanString(record["id"])
		if id == "" {
			continue
		}
		vendor := firstString(cleanString(record["vendor"]), darwinPCIVendor(record["vendor_id"]))
		adapter := NetworkAdapter{
			ID:             id,
			Name:           firstString(cleanString(record["name"]), id),
			Model:          cleanString(record["model"]),
			Vendor:         vendor,
			PhysicalMedium: normalizeDarwinNetworkMedium(record["physical_medium"]),
			MACAddress:     normalizeMAC(record["mac_address"]),
			PNPID:          cleanString(record["pnp_id"]),
		}
		if existing, ok := byID[id]; ok {
			adapter = mergeDarwinNetworkAdapter(existing, adapter)
		}
		byID[id] = adapter
	}
	adapters := make([]NetworkAdapter, 0, len(byID))
	for _, adapter := range byID {
		adapters = append(adapters, adapter)
	}
	sort.Slice(adapters, func(i, j int) bool { return adapters[i].ID < adapters[j].ID })
	return adapters
}

func mergeDarwinNetworkAdapter(left, right NetworkAdapter) NetworkAdapter {
	if left.Name == "" || left.Name == left.ID {
		left.Name = firstString(right.Name, left.Name)
	}
	left.Model = firstString(left.Model, right.Model)
	left.Vendor = firstString(left.Vendor, right.Vendor)
	left.PhysicalMedium = firstString(left.PhysicalMedium, right.PhysicalMedium)
	left.MACAddress = firstString(left.MACAddress, right.MACAddress)
	left.PNPID = firstString(left.PNPID, right.PNPID)
	return left
}

func normalizeDarwinNetworkMedium(value string) string {
	normalized := strings.ToLower(cleanString(value))
	if strings.Contains(normalized, "wireless") || strings.Contains(normalized, "wifi") || strings.Contains(normalized, "wi-fi") || strings.Contains(normalized, "wlan") || strings.Contains(normalized, "80211") {
		return "wireless_lan"
	}
	if normalized != "" {
		return "ethernet"
	}
	return ""
}

func collectDarwinGPUs(records []darwinRecord) []GPU {
	byID := make(map[string]GPU)
	for _, record := range records {
		if record["kind"] != "gpu" {
			continue
		}
		pnpID := cleanString(record["pnp_id"])
		id := firstString(cleanString(record["id"]), pnpID)
		if id == "" {
			continue
		}
		gpu := GPU{
			ID:             id,
			PNPID:          pnpID,
			Name:           cleanString(record["name"]),
			Manufacturer:   firstString(cleanString(record["manufacturer"]), darwinPCIVendor(record["vendor_id"])),
			VideoProcessor: firstString(cleanString(record["video_processor"]), cleanString(record["name"])),
		}
		if existing, ok := byID[id]; ok {
			gpu = mergeDarwinGPU(existing, gpu)
		}
		byID[id] = gpu
	}
	gpus := make([]GPU, 0, len(byID))
	for _, gpu := range byID {
		gpus = append(gpus, gpu)
	}
	sort.Slice(gpus, func(i, j int) bool { return gpus[i].ID < gpus[j].ID })
	return gpus
}

func mergeDarwinGPU(left, right GPU) GPU {
	left.PNPID = firstString(left.PNPID, right.PNPID)
	left.Name = firstString(left.Name, right.Name)
	left.Manufacturer = firstString(left.Manufacturer, right.Manufacturer)
	left.VideoProcessor = firstString(left.VideoProcessor, right.VideoProcessor)
	return left
}

func darwinPCIVendor(value string) string {
	vendor := parseUint64(value) & 0xffff
	switch vendor {
	case 0x1002:
		return "AMD"
	case 0x106b:
		return "Apple Inc."
	case 0x10de:
		return "NVIDIA"
	case 0x14e4:
		return "Broadcom"
	case 0x8086:
		return "Intel"
	default:
		return ""
	}
}

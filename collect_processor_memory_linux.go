//go:build linux && (amd64 || arm64)

package hwdiscovery

import (
	"math"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type linuxCPUPackage struct {
	logicalCPUs  int
	cores        map[string]struct{}
	manufacturer string
	model        string
	maxClockMHz  uint32
}

func collectLinuxProcessors(source linuxSource) []Processor {
	packages := linuxCPUTopology(source)
	applyCPUInfo(source, packages, len(packages) > 0)
	dmiProcessors := parseDMIProcessors(source)

	packageIDs := make([]int, 0, len(packages))
	for id := range packages {
		packageIDs = append(packageIDs, id)
	}
	sort.Ints(packageIDs)
	processors := make([]Processor, 0, maxInt(len(packageIDs), len(dmiProcessors)))
	for index, packageID := range packageIDs {
		row := packages[packageID]
		processor := Processor{
			ID:                    "CPU" + strconv.Itoa(packageID),
			Manufacturer:          row.manufacturer,
			Model:                 row.model,
			Architecture:          linuxArchitecture(runtime.GOARCH),
			PhysicalCoreCount:     uint32(len(row.cores)),
			LogicalProcessorCount: uint32(row.logicalCPUs),
			MaxClockMHz:           row.maxClockMHz,
		}
		if index < len(dmiProcessors) {
			enrichLinuxProcessor(&processor, dmiProcessors[index])
		}
		processors = append(processors, processor)
	}
	for index := len(processors); index < len(dmiProcessors); index++ {
		processor := Processor{ID: "CPU" + strconv.Itoa(index), Architecture: linuxArchitecture(runtime.GOARCH)}
		enrichLinuxProcessor(&processor, dmiProcessors[index])
		processors = append(processors, processor)
	}
	return processors
}

func linuxCPUTopology(source linuxSource) map[int]*linuxCPUPackage {
	root := source.sys("devices", "system", "cpu")
	packages := make(map[int]*linuxCPUPackage)
	for _, name := range sortedDirNames(root) {
		cpuID, found := cpuDirectoryID(name)
		if !found {
			continue
		}
		path := filepath.Join(root, name)
		packageID := 0
		if value := readClean(filepath.Join(path, "topology", "physical_package_id")); value != "" {
			if parsed, ok := parsePositiveInt(value); ok {
				packageID = parsed
			}
		}
		row := packages[packageID]
		if row == nil {
			row = &linuxCPUPackage{cores: make(map[string]struct{})}
			packages[packageID] = row
		}
		row.logicalCPUs++
		coreID := strconv.Itoa(cpuID)
		if value := readClean(filepath.Join(path, "topology", "core_id")); value != "" {
			if parsed, ok := parsePositiveInt(value); ok {
				coreID = strconv.Itoa(parsed)
			}
		}
		if dieID := readClean(filepath.Join(path, "topology", "die_id")); dieID != "" {
			coreID = dieID + ":" + coreID
		}
		row.cores[coreID] = struct{}{}
		if frequency, ok := readUint(filepath.Join(path, "cpufreq", "cpuinfo_max_freq"), 64); ok {
			mhz := frequency / 1000
			if mhz <= math.MaxUint32 && uint32(mhz) > row.maxClockMHz {
				row.maxClockMHz = uint32(mhz)
			}
		}
	}
	return packages
}

func cpuDirectoryID(name string) (int, bool) {
	if !strings.HasPrefix(name, "cpu") || len(name) == 3 {
		return 0, false
	}
	return parsePositiveInt(name[3:])
}

func applyCPUInfo(source linuxSource, packages map[int]*linuxCPUPackage, topologyAvailable bool) {
	data, err := readLinuxFile(source.proc("cpuinfo"), maxLinuxMetadataBytes)
	if err != nil {
		return
	}
	for _, stanza := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
		properties := colonProperties(stanza)
		packageID := 0
		if parsed, ok := parsePositiveInt(properties["physical id"]); ok {
			packageID = parsed
		}
		row := packages[packageID]
		if row == nil {
			row = &linuxCPUPackage{cores: make(map[string]struct{})}
			packages[packageID] = row
		}
		if !topologyAvailable {
			row.logicalCPUs++
			coreID := firstString(properties["core id"], properties["processor"])
			if coreID == "" {
				coreID = strconv.Itoa(row.logicalCPUs - 1)
			}
			row.cores[coreID] = struct{}{}
		}
		row.manufacturer = firstString(row.manufacturer, cleanString(properties["vendor_id"]), armImplementer(properties["cpu implementer"]))
		row.model = firstString(row.model, cleanString(properties["model name"]), cleanString(properties["processor"]), cleanString(properties["cpu model"]), cleanString(properties["cpu part"]))
	}
}

func colonProperties(data string) map[string]string {
	properties := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		key, value, found := strings.Cut(line, ":")
		if found {
			properties[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	return properties
}

func armImplementer(value string) string {
	implementers := map[string]string{
		"0x41": "Arm", "0x42": "Broadcom", "0x43": "Cavium", "0x44": "DEC",
		"0x46": "Fujitsu", "0x48": "HiSilicon", "0x4e": "NVIDIA", "0x50": "APM",
		"0x51": "Qualcomm", "0x53": "Samsung", "0x61": "Apple", "0x69": "Intel",
	}
	return implementers[strings.ToLower(cleanString(value))]
}

func parseDMIProcessors(source linuxSource) []Processor {
	records := readDMIRecords(source, 4)
	processors := make([]Processor, 0, len(records))
	for _, record := range records {
		if len(record.formatted) > 5 && record.formatted[5] != 0 && record.formatted[5] != 3 {
			continue
		}
		if len(record.formatted) > 24 && record.formatted[24]&0x40 == 0 {
			continue
		}
		processor := Processor{
			Manufacturer: record.stringAt(7),
			Model:        record.stringAt(16),
			SerialNumber: record.stringAt(32),
			Socket:       record.stringAt(4),
			MaxClockMHz:  uint32(record.uint16At(20)),
		}
		processor.PhysicalCoreCount = uint32(dmiCount(record, 35, 42))
		processor.LogicalProcessorCount = uint32(dmiCount(record, 37, 46))
		processors = append(processors, processor)
	}
	return processors
}

func dmiCount(record dmiRecord, byteOffset, wordOffset int) uint16 {
	if byteOffset >= len(record.formatted) {
		return 0
	}
	value := record.formatted[byteOffset]
	if value == 0xff {
		return record.uint16At(wordOffset)
	}
	return uint16(value)
}

func enrichLinuxProcessor(processor *Processor, dmi Processor) {
	processor.Manufacturer = firstString(dmi.Manufacturer, processor.Manufacturer)
	processor.Model = firstString(dmi.Model, processor.Model)
	processor.SerialNumber = firstString(dmi.SerialNumber, processor.SerialNumber)
	processor.Socket = firstString(dmi.Socket, processor.Socket)
	if processor.PhysicalCoreCount == 0 {
		processor.PhysicalCoreCount = dmi.PhysicalCoreCount
	}
	if processor.LogicalProcessorCount == 0 {
		processor.LogicalProcessorCount = dmi.LogicalProcessorCount
	}
	if processor.MaxClockMHz == 0 {
		processor.MaxClockMHz = dmi.MaxClockMHz
	}
}

func collectLinuxMemory(source linuxSource) *Memory {
	installed := linuxMemTotal(source)
	modules := parseDMIMemoryModules(source)
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

func linuxMemTotal(source linuxSource) uint64 {
	data, err := readLinuxFile(source.proc("meminfo"), maxLinuxAttributeBytes)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "MemTotal:" || fields[2] != "kB" {
			continue
		}
		kilobytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || kilobytes > math.MaxUint64/1024 {
			return 0
		}
		return kilobytes * 1024
	}
	return 0
}

func parseDMIMemoryModules(source linuxSource) []MemoryModule {
	modules := make([]MemoryModule, 0)
	for _, record := range readDMIRecords(source, 17) {
		capacity, installed := dmiMemoryCapacity(record)
		if !installed {
			continue
		}
		module := MemoryModule{
			Bank:               record.stringAt(17),
			Location:           record.stringAt(16),
			Vendor:             record.stringAt(23),
			PartNumber:         record.stringAt(26),
			SerialNumber:       record.stringAt(24),
			CapacityBytes:      capacity,
			ConfiguredSpeedMTs: dmiMemorySpeed(record, 32, 88),
			RatedSpeedMTs:      dmiMemorySpeed(record, 21, 84),
		}
		if len(record.formatted) > 18 {
			module.MemoryType = smbiosMemoryType(uint32(record.formatted[18]))
		}
		if len(record.formatted) > 14 {
			module.FormFactor = memoryFormFactor(uint16(record.formatted[14]))
		}
		modules = append(modules, module)
	}
	sort.Slice(modules, func(i, j int) bool {
		left, right := modules[i], modules[j]
		if left.Location != right.Location {
			return left.Location < right.Location
		}
		if left.Bank != right.Bank {
			return left.Bank < right.Bank
		}
		if left.SerialNumber != right.SerialNumber {
			return left.SerialNumber < right.SerialNumber
		}
		return left.PartNumber < right.PartNumber
	})
	return modules
}

func dmiMemoryCapacity(record dmiRecord) (uint64, bool) {
	size := record.uint16At(12)
	switch size {
	case 0, 0xffff:
		return 0, false
	case 0x7fff:
		extended := uint64(record.uint32At(28) & 0x7fffffff)
		if extended == 0 || extended > math.MaxUint64/(1024*1024) {
			return 0, false
		}
		return extended * 1024 * 1024, true
	default:
		units := uint64(1024 * 1024)
		if size&0x8000 != 0 {
			units = 1024
			size &= 0x7fff
		}
		return uint64(size) * units, size != 0
	}
}

func dmiMemorySpeed(record dmiRecord, wordOffset, extendedOffset int) uint32 {
	speed := record.uint16At(wordOffset)
	if speed == 0 || speed == 0xffff {
		if speed == 0xffff {
			return record.uint32At(extendedOffset)
		}
		return 0
	}
	return uint32(speed)
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

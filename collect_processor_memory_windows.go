//go:build windows && (amd64 || arm64)

package hwdiscovery

import "sort"

type win32Processor struct {
	DeviceID                  *string
	ProcessorId               *string
	Manufacturer              *string
	Name                      *string
	SerialNumber              *string
	Architecture              *uint16
	SocketDesignation         *string
	NumberOfCores             *uint32
	NumberOfLogicalProcessors *uint32
	MaxClockSpeed             *uint32
}

type win32PhysicalMemory struct {
	BankLabel            *string
	DeviceLocator        *string
	Manufacturer         *string
	PartNumber           *string
	SerialNumber         *string
	Capacity             *uint64
	ConfiguredClockSpeed *uint32
	Speed                *uint32
	SMBIOSMemoryType     *uint32
	MemoryType           *uint16
	FormFactor           *uint16
}

func collectProcessors(q queryer) []Processor {
	var rows []win32Processor
	if queryClass(q, cimv2Namespace, "Win32_Processor", &rows) != nil {
		return nil
	}

	processors := make([]Processor, 0, len(rows))
	for _, row := range rows {
		processor := Processor{
			ID:           firstString(cleanStringPtr(row.DeviceID), cleanStringPtr(row.ProcessorId)),
			Manufacturer: cleanStringPtr(row.Manufacturer),
			Model:        cleanStringPtr(row.Name),
			SerialNumber: cleanStringPtr(row.SerialNumber),
			Architecture: normalizeProcessorArchitecture(row.Architecture),
			Socket:       cleanStringPtr(row.SocketDesignation),
		}
		if row.NumberOfCores != nil {
			processor.PhysicalCoreCount = *row.NumberOfCores
		}
		if row.NumberOfLogicalProcessors != nil {
			processor.LogicalProcessorCount = *row.NumberOfLogicalProcessors
		}
		if row.MaxClockSpeed != nil {
			processor.MaxClockMHz = *row.MaxClockSpeed
		}
		if processor.ID == "" {
			continue
		}
		processors = append(processors, processor)
	}
	sort.Slice(processors, func(i, j int) bool { return processors[i].ID < processors[j].ID })
	return processors
}

func collectMemory(q queryer, installedPhysicalBytes uint64) *Memory {
	var rows []win32PhysicalMemory
	if queryClass(q, cimv2Namespace, "Win32_PhysicalMemory", &rows) != nil {
		if installedPhysicalBytes == 0 {
			return nil
		}
		return &Memory{InstalledPhysicalBytes: installedPhysicalBytes}
	}

	modules := make([]MemoryModule, 0, len(rows))
	var moduleCapacity uint64
	capacityOverflow := false
	for _, row := range rows {
		module := MemoryModule{
			Bank:         cleanStringPtr(row.BankLabel),
			Location:     cleanStringPtr(row.DeviceLocator),
			Vendor:       cleanStringPtr(row.Manufacturer),
			PartNumber:   cleanStringPtr(row.PartNumber),
			SerialNumber: cleanStringPtr(row.SerialNumber),
			MemoryType:   normalizeMemoryType(row.SMBIOSMemoryType, row.MemoryType),
			FormFactor:   normalizeMemoryFormFactor(row.FormFactor),
		}
		if row.Capacity != nil {
			module.CapacityBytes = *row.Capacity
			if ^uint64(0)-moduleCapacity >= *row.Capacity {
				moduleCapacity += *row.Capacity
			} else {
				capacityOverflow = true
			}
		}
		if row.ConfiguredClockSpeed != nil {
			module.ConfiguredSpeedMTs = *row.ConfiguredClockSpeed
		}
		if row.Speed != nil {
			module.RatedSpeedMTs = *row.Speed
		}
		if module == (MemoryModule{}) {
			continue
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

	if installedPhysicalBytes == 0 && !capacityOverflow {
		installedPhysicalBytes = moduleCapacity
	}
	if installedPhysicalBytes == 0 && len(modules) == 0 {
		return nil
	}
	return &Memory{InstalledPhysicalBytes: installedPhysicalBytes, Modules: modules}
}

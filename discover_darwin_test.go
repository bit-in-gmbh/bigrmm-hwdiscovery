//go:build darwin

package hwdiscovery

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"runtime"
	"strconv"
	"testing"
)

func TestDarwinCompleteInventoryAndDeterministicOrder(t *testing.T) {
	sysctls := darwinSysctlValues{
		strings: map[string]string{
			"hw.model":                 "MacBookPro18,3",
			"machdep.cpu.brand_string": "Apple M2 Pro",
		},
		uints: map[string]uint64{
			"hw.memsize":          8 << 30,
			"hw.packages":         1,
			"hw.physicalcpu":      8,
			"hw.logicalcpu":       10,
			"hw.cpufrequency_max": 3_200_000_000,
		},
	}
	native := darwinNativeInventory{
		system: darwinRecord{
			"manufacturer": "Apple Inc.", "model": "MacBookPro18,3", "product_name": "MacBook Pro",
			"model_number": "A2485", "serial_number": "SYSTEM-1", "uuid": "ABCDEF1234567890ABCDEF1234567890",
			"target_type": "J316sAP", "board_id": "Mac-TEST", "firmware_version": "10151.1.1",
			"firmware_date": "09/16/2026",
		},
		smbios: darwinMemoryFixture(),
		storage: []darwinRecord{
			{"kind": "volume", "parent": "disk0s2", "id": "VOLUME-B", "label": "Data", "filesystem": "apfs", "capacity_bytes": "800000", "mount_point": "/System/Volumes/Data"},
			{"kind": "partition", "parent": "disk0", "id": "disk0s2", "index": "2", "size_bytes": "800000", "starting_offset_bytes": "201024"},
			{"kind": "disk", "id": "disk0", "index": "0", "pnp_id": "IOService:/disk0", "model": "APPLE SSD TEST", "serial_number": "DISK-1", "capacity_bytes": "1000000", "logical_sector_size_bytes": "4096", "physical_sector_size_bytes": "4096", "media_type": "Solid State", "bus_type": "NVMe", "partition_table_type": "GUID_partition_scheme"},
			{"kind": "partition", "parent": "disk0", "id": "disk0s1", "index": "1", "size_bytes": "200000", "starting_offset_bytes": "1024"},
			{"kind": "volume", "parent": "disk0s1", "id": "VOLUME-A", "label": "EFI", "filesystem": "msdos", "capacity_bytes": "200000", "mount_point": "/Volumes/EFI"},
		},
		network: []darwinRecord{
			{"kind": "network", "id": "en1", "name": "Ethernet", "model": "USB Ethernet", "vendor_id": "0x8086", "physical_medium": "ethernet", "mac_address": "00-11-22-aa-bb-cc", "pnp_id": "IOService:/en1"},
			{"kind": "network", "id": "en0", "name": "Wi-Fi", "model": "Wireless", "vendor_id": "0x14e4", "physical_medium": "wireless_lan", "mac_address": "00:11:22:33:44:55", "pnp_id": "IOService:/en0"},
			{"kind": "network", "id": "en0", "name": "duplicate"},
		},
		gpus: []darwinRecord{
			{"kind": "gpu", "id": "0x20", "pnp_id": "IOService:/gpu-b", "name": "GPU B", "vendor_id": "0x1002"},
			{"kind": "gpu", "id": "0x10", "pnp_id": "IOService:/gpu-a", "name": "GPU A", "manufacturer": "Apple Inc.", "video_processor": "AGX"},
			{"kind": "gpu", "id": "0x10", "pnp_id": "IOService:/gpu-a", "name": "GPU A"},
		},
	}

	first := discoverDarwin(sysctls, native)
	second := discoverDarwin(sysctls, native)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first inventory: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second inventory: %v", err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("Darwin discovery is not deterministic\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}

	if first.System == nil || first.System.Model != "MacBookPro18,3" || first.System.UUID != "abcdef12-3456-7890-abcd-ef1234567890" || first.System.SystemType != darwinArchitecture(runtime.GOARCH) {
		t.Fatalf("unexpected system: %#v", first.System)
	}
	if first.System.Chassis == nil || first.System.Chassis.Type != "notebook" || first.System.Baseboard == nil || first.System.Baseboard.Product != "Mac-TEST" || first.System.Firmware == nil || first.System.Firmware.ReleaseDate != "2026-09-16" {
		t.Fatalf("unexpected system components: %#v", first.System)
	}
	if len(first.Processors) != 1 || first.Processors[0].Manufacturer != "Apple Inc." || first.Processors[0].PhysicalCoreCount != 8 || first.Processors[0].LogicalProcessorCount != 10 || first.Processors[0].MaxClockMHz != 3200 {
		t.Fatalf("unexpected processors: %#v", first.Processors)
	}
	if first.Memory == nil || first.Memory.InstalledPhysicalBytes != 8<<30 || len(first.Memory.Modules) != 1 || first.Memory.Modules[0].MemoryType != "ddr5" || first.Memory.Modules[0].ConfiguredSpeedMTs != 5200 {
		t.Fatalf("unexpected memory: %#v", first.Memory)
	}
	if len(first.Disks) != 1 || first.Disks[0].ID != "/dev/disk0" || first.Disks[0].Vendor != "Apple Inc." || first.Disks[0].MediaType != "ssd" || first.Disks[0].BusType != "nvme" || first.Disks[0].PartitionTableType != "gpt" || len(first.Disks[0].Partitions) != 2 {
		t.Fatalf("unexpected disks: %#v", first.Disks)
	}
	if first.Disks[0].Partitions[0].ID != "/dev/disk0s1" || len(first.Disks[0].Partitions[1].Volumes) != 1 || first.Disks[0].Partitions[1].Volumes[0].MountPoints[0] != "/System/Volumes/Data" {
		t.Fatalf("unexpected partitions or volumes: %#v", first.Disks[0].Partitions)
	}
	if len(first.NetworkAdapters) != 2 || first.NetworkAdapters[0].ID != "en0" || first.NetworkAdapters[0].Vendor != "Broadcom" || first.NetworkAdapters[0].PhysicalMedium != "wireless_lan" || first.NetworkAdapters[1].MACAddress != "00:11:22:AA:BB:CC" {
		t.Fatalf("unexpected network adapters: %#v", first.NetworkAdapters)
	}
	if len(first.GPUs) != 2 || first.GPUs[0].ID != "0x10" || first.GPUs[0].VideoProcessor != "AGX" || first.GPUs[1].Manufacturer != "AMD" {
		t.Fatalf("unexpected GPUs: %#v", first.GPUs)
	}
}

func TestDarwinMalformedInputsAreIsolated(t *testing.T) {
	sysctls := darwinSysctlValues{
		strings: map[string]string{"hw.model": "Macmini9,1"},
		uints:   map[string]uint64{"hw.memsize": 16 << 30, "hw.packages": 1, "hw.physicalcpu": 8, "hw.logicalcpu": 8},
	}
	native := darwinNativeInventory{
		smbios: []byte{17, 255, 0, 0, 0, 0},
		storage: []darwinRecord{
			{"kind": "disk", "id": "disk2", "index": "bad", "capacity_bytes": "18446744073709551616"},
			{"kind": "partition", "parent": "missing", "id": "disk9s1"},
		},
		network: []darwinRecord{{"kind": "network", "id": "en0", "mac_address": "invalid"}},
		gpus:    []darwinRecord{{"kind": "gpu"}},
	}

	inventory := discoverDarwin(sysctls, native)
	if inventory.System == nil || inventory.Memory == nil || inventory.Memory.InstalledPhysicalBytes != 16<<30 || len(inventory.Processors) != 1 || len(inventory.Disks) != 1 || len(inventory.NetworkAdapters) != 1 {
		t.Fatalf("malformed optional data affected independent entities: %#v", inventory)
	}
	if inventory.Disks[0].Index != nil || inventory.Disks[0].CapacityBytes != 0 || inventory.NetworkAdapters[0].MACAddress != "" || len(inventory.GPUs) != 0 {
		t.Fatalf("malformed values were accepted: %#v", inventory)
	}
}

func TestDarwinInvalidPackageCountIsIsolated(t *testing.T) {
	for _, packages := range []uint64{1025, math.MaxInt64, math.MaxUint64} {
		t.Run(strconv.FormatUint(packages, 10), func(t *testing.T) {
			inventory := discoverDarwin(darwinSysctlValues{
				strings: map[string]string{"hw.model": "Macmini9,1"},
				uints:   map[string]uint64{"hw.memsize": 16 << 30, "hw.packages": packages},
			}, darwinNativeInventory{})
			if len(inventory.Processors) != 0 {
				t.Fatalf("invalid package count produced %d processors", len(inventory.Processors))
			}
			if inventory.System == nil || inventory.Memory == nil || inventory.Memory.InstalledPhysicalBytes != 16<<30 {
				t.Fatal("invalid package count discarded independent inventory")
			}
		})
	}
	for _, counts := range []struct{ physical, logical uint64 }{{1, 8}, {8, 1}} {
		if got := collectDarwinProcessors(darwinSysctlValues{uints: map[string]uint64{
			"hw.packages": 2, "hw.physicalcpu": counts.physical, "hw.logicalcpu": counts.logical,
		}}); len(got) != 0 {
			t.Fatalf("package count exceeding processor topology was accepted: %#v", got)
		}
	}
	if got := collectDarwinProcessors(darwinSysctlValues{uints: map[string]uint64{
		"hw.packages": 2, "hw.physicalcpu": 8, "hw.logicalcpu": 16,
	}}); len(got) != 2 || got[0].PhysicalCoreCount != 4 || got[0].LogicalProcessorCount != 8 {
		t.Fatalf("valid multi-package topology changed: %#v", got)
	}
}

func TestDiscoverLiveDarwin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Darwin discovery in short mode")
	}
	inventory := Discover()
	if _, err := json.Marshal(inventory); err != nil {
		t.Fatalf("marshal live inventory: %v", err)
	}
	partitions, volumes := 0, 0
	for _, disk := range inventory.Disks {
		partitions += len(disk.Partitions)
		for _, partition := range disk.Partitions {
			volumes += len(partition.Volumes)
		}
	}
	t.Logf("live inventory: system=%t memory=%t processors=%d disks=%d partitions=%d volumes=%d network_adapters=%d gpus=%d", inventory.System != nil, inventory.Memory != nil, len(inventory.Processors), len(inventory.Disks), partitions, volumes, len(inventory.NetworkAdapters), len(inventory.GPUs))
}

func darwinMemoryFixture() []byte {
	formatted := make([]byte, 92)
	formatted[0], formatted[1] = 17, byte(len(formatted))
	binary.LittleEndian.PutUint16(formatted[12:14], 8192)
	formatted[14], formatted[16], formatted[17], formatted[18] = 12, 1, 2, 34
	binary.LittleEndian.PutUint16(formatted[21:23], 5600)
	formatted[23], formatted[24], formatted[26] = 3, 4, 5
	binary.LittleEndian.PutUint16(formatted[32:34], 5200)
	data := append([]byte{}, formatted...)
	for _, value := range []string{"DIMM_A", "BANK 0", "Memory Co", "MEM-A", "PART-A"} {
		data = append(data, value...)
		data = append(data, 0)
	}
	data = append(data, 0)
	data = append(data, 127, 4, 0xff, 0xff, 0, 0)
	return data
}

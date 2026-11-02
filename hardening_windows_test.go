//go:build windows && (amd64 || arm64)

package hwdiscovery

import "testing"

func TestMemoryCapacityOverflowOmitsOnlyDerivedTotal(t *testing.T) {
	for _, installed := range []uint64{0, 32 << 30} {
		q := &fixtureQueryer{rows: map[string]any{
			"Win32_PhysicalMemory": []win32PhysicalMemory{
				{DeviceLocator: pointer("DIMM_A"), Capacity: pointer(^uint64(0))},
				{DeviceLocator: pointer("DIMM_B"), Capacity: pointer(uint64(1))},
				{DeviceLocator: pointer("DIMM_C"), Capacity: pointer(uint64(2))},
			},
		}}
		memory := collectMemory(q, installed)
		if memory == nil || len(memory.Modules) != 3 {
			t.Fatalf("overflow discarded memory modules: %#v", memory)
		}
		if memory.InstalledPhysicalBytes != installed {
			t.Fatalf("overflow produced a partial total or replaced system total: got %d, want %d", memory.InstalledPhysicalBytes, installed)
		}
		if memory.Modules[0].CapacityBytes != ^uint64(0) {
			t.Fatal("overflow changed the reported module capacity")
		}
	}
}

func TestMemoryCapacityFallbackAcceptsExactUint64Limit(t *testing.T) {
	q := &fixtureQueryer{rows: map[string]any{
		"Win32_PhysicalMemory": []win32PhysicalMemory{
			{Capacity: pointer(^uint64(0) - 1)},
			{Capacity: pointer(uint64(1))},
		},
	}}
	if memory := collectMemory(q, 0); memory == nil || memory.InstalledPhysicalBytes != ^uint64(0) {
		t.Fatalf("valid total at uint64 limit was omitted: %#v", memory)
	}
}

func TestChassisTypeRejectsOutOfRangeValues(t *testing.T) {
	if got := normalizeChassisType([]int32{-1, 0x10009}); got != "" {
		t.Fatalf("invalid chassis value narrowed to a valid type: %q", got)
	}
	if got := normalizeChassisType([]int32{0x10009, 3}); got != "desktop" {
		t.Fatalf("invalid value hid later valid chassis type: %q", got)
	}
}

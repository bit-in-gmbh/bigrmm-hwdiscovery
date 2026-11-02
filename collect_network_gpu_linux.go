//go:build linux && (amd64 || arm64)

package hwdiscovery

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func collectLinuxNetworkAdapters(source linuxSource, pci pciDatabase) []NetworkAdapter {
	root := source.sys("class", "net")
	adapters := make([]NetworkAdapter, 0)
	for _, name := range sortedDirNames(root) {
		path := filepath.Join(root, name)
		devicePath := filepath.Join(path, "device")
		resolved, err := filepath.EvalSymlinks(devicePath)
		if err != nil || !pathWithin(resolved, source.sysRoot) || strings.Contains(filepath.ToSlash(resolved), "/devices/virtual/") {
			continue
		}
		ifindex := readClean(filepath.Join(path, "ifindex"))
		udev := source.udevProperties("n" + ifindex)
		properties := deviceProperties(devicePath, source.sysRoot)
		vendor, model := linuxDeviceNames(devicePath, udev, pci, source.sysRoot)
		adapter := NetworkAdapter{
			ID:             name,
			Name:           name,
			Model:          model,
			Vendor:         vendor,
			PhysicalMedium: linuxNetworkMedium(path),
			MACAddress:     linuxPermanentMAC(path, udev),
			PNPID:          properties["MODALIAS"],
		}
		adapters = append(adapters, adapter)
	}
	sort.Slice(adapters, func(i, j int) bool { return adapters[i].ID < adapters[j].ID })
	return adapters
}

func linuxNetworkMedium(path string) string {
	if _, err := os.Stat(filepath.Join(path, "wireless")); err == nil {
		return "wireless_lan"
	}
	if properties := readProperties(filepath.Join(path, "uevent")); properties["DEVTYPE"] == "wlan" {
		return "wireless_lan"
	}
	value, ok := readUint(filepath.Join(path, "type"), 32)
	if !ok {
		return ""
	}
	media := map[uint64]string{
		1: "ethernet", 6: "ieee_802", 19: "atm", 24: "ieee_1394", 32: "infiniband",
		256: "slip", 512: "ppp", 768: "tunnel",
	}
	return media[value]
}

func linuxPermanentMAC(path string, udev map[string]string) string {
	if assignment, ok := readUint(filepath.Join(path, "addr_assign_type"), 8); ok && assignment == 0 {
		return normalizeMAC(readClean(filepath.Join(path, "address")))
	}
	name := udev["ID_NET_NAME_MAC"]
	if len(name) >= 12 {
		candidate := name[len(name)-12:]
		if _, err := strconv.ParseUint(candidate, 16, 64); err == nil {
			return normalizeMAC(candidate[0:2] + ":" + candidate[2:4] + ":" + candidate[4:6] + ":" + candidate[6:8] + ":" + candidate[8:10] + ":" + candidate[10:12])
		}
	}
	return ""
}

func linuxDeviceNames(devicePath string, udev map[string]string, pci pciDatabase, sysRoot string) (string, string) {
	vendor := firstString(udev["ID_VENDOR_FROM_DATABASE"], udev["ID_VENDOR"])
	model := firstString(udev["ID_MODEL_FROM_DATABASE"], udev["ID_MODEL"])
	pciVendor := readClean(filepath.Join(devicePath, "vendor"))
	pciDevice := readClean(filepath.Join(devicePath, "device"))
	if databaseVendor, databaseModel := pci.lookup(pciVendor, pciDevice); databaseVendor != "" || databaseModel != "" {
		vendor = firstString(vendor, databaseVendor)
		model = firstString(model, databaseModel)
	}
	vendor = firstString(vendor, ancestorAttribute(devicePath, "manufacturer", sysRoot))
	model = firstString(model, ancestorAttribute(devicePath, "product", sysRoot))
	return cleanString(vendor), cleanString(model)
}

func ancestorAttribute(start, name, stop string) string {
	path, err := filepath.EvalSymlinks(start)
	if err != nil {
		return ""
	}
	for current := path; current != filepath.Dir(current); current = filepath.Dir(current) {
		if !pathWithin(current, stop) {
			break
		}
		if value := readClean(filepath.Join(current, name)); value != "" {
			return value
		}
		if current == stop {
			break
		}
	}
	return ""
}

func collectLinuxGPUs(source linuxSource, pci pciDatabase) []GPU {
	devices := make(map[string]string)
	pciRoot := source.sys("bus", "pci", "devices")
	for _, name := range sortedDirNames(pciRoot) {
		path := filepath.Join(pciRoot, name)
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || !pathWithin(resolved, source.sysRoot) {
			continue
		}
		class, ok := readUint(filepath.Join(path, "class"), 32)
		if !ok || (class>>16)&0xff != 3 {
			continue
		}
		devices[resolved] = path
	}

	drmRoot := source.sys("class", "drm")
	for _, name := range sortedDirNames(drmRoot) {
		if !drmCardName(name) {
			continue
		}
		path := filepath.Join(drmRoot, name, "device")
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || !pathWithin(resolved, source.sysRoot) || strings.Contains(filepath.ToSlash(resolved), "/devices/virtual/") {
			continue
		}
		if _, found := devices[resolved]; !found {
			devices[resolved] = path
		}
	}

	gpus := make([]GPU, 0, len(devices))
	for resolved, path := range devices {
		properties := deviceProperties(path, source.sysRoot)
		slot := properties["PCI_SLOT_NAME"]
		udev := map[string]string(nil)
		if slot != "" {
			udev = source.udevProperties("+pci:" + slot)
		}
		vendor, model := linuxDeviceNames(path, udev, pci, source.sysRoot)
		if model == "" {
			model = firstNULFile(filepath.Join(path, "of_node", "compatible"))
		}
		id := slot
		if id == "" {
			relative, err := filepath.Rel(source.sysRoot, resolved)
			if err == nil {
				id = filepath.ToSlash(relative)
			}
		}
		id = cleanString(id)
		if id == "" {
			continue
		}
		name := firstString(cleanString(strings.TrimSpace(vendor+" "+model)), model, vendor)
		gpus = append(gpus, GPU{
			ID:             id,
			PNPID:          properties["MODALIAS"],
			Name:           name,
			Manufacturer:   vendor,
			VideoProcessor: model,
		})
	}
	sort.Slice(gpus, func(i, j int) bool { return gpus[i].ID < gpus[j].ID })
	return gpus
}

func drmCardName(name string) bool {
	if !strings.HasPrefix(name, "card") || len(name) == 4 {
		return false
	}
	_, err := strconv.ParseUint(name[4:], 10, 32)
	return err == nil
}

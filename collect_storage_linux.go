//go:build linux && (amd64 || arm64)

package hwdiscovery

import (
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type linuxBlock struct {
	name     string
	path     string
	resolved string
	dev      string
	uevent   map[string]string
	udev     map[string]string
}

type linuxPartitionLocation struct {
	disk      int
	partition int
}

type linuxMount struct {
	filesystem string
	source     string
	points     []string
}

func collectLinuxDisks(source linuxSource) []Disk {
	blocks := scanLinuxBlocks(source)
	diskNames := make([]string, 0)
	for name, block := range blocks {
		if isLinuxPhysicalDisk(source, block) {
			diskNames = append(diskNames, name)
		}
	}
	sort.Slice(diskNames, func(i, j int) bool { return naturalLess(diskNames[i], diskNames[j]) })

	disks := make([]Disk, 0, len(diskNames))
	locations := make(map[string]linuxPartitionLocation)
	for diskIndex, name := range diskNames {
		block := blocks[name]
		index := uint32(diskIndex)
		disk := linuxDiskFromBlock(source, block, &index)
		partitionNames := childPartitionNames(block, blocks)
		for _, partitionName := range partitionNames {
			partitionBlock := blocks[partitionName]
			partitionNumber, ok := readUint(filepath.Join(partitionBlock.path, "partition"), 32)
			if !ok || partitionNumber > math.MaxUint32 {
				continue
			}
			partitionIndex := uint32(partitionNumber)
			partition := Partition{ID: filepath.Join(source.devRoot, partitionName), Index: &partitionIndex}
			partition.SizeBytes, _ = linuxSectorBytes(filepath.Join(partitionBlock.path, "size"))
			partition.StartingOffsetBytes, _ = linuxSectorBytes(filepath.Join(partitionBlock.path, "start"))
			locations[partitionName] = linuxPartitionLocation{disk: len(disks), partition: len(disk.Partitions)}
			disk.Partitions = append(disk.Partitions, partition)
		}
		disks = append(disks, disk)
	}

	attachLinuxVolumes(source, blocks, locations, disks)
	for index := range disks {
		sort.Slice(disks[index].Partitions, func(i, j int) bool {
			left, right := disks[index].Partitions[i], disks[index].Partitions[j]
			if left.Index != nil && right.Index != nil && *left.Index != *right.Index {
				return *left.Index < *right.Index
			}
			return left.ID < right.ID
		})
	}
	return disks
}

func scanLinuxBlocks(source linuxSource) map[string]linuxBlock {
	root := source.sys("class", "block")
	blocks := make(map[string]linuxBlock)
	for _, name := range sortedDirNames(root) {
		path := filepath.Join(root, name)
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || !pathWithin(resolved, source.sysRoot) {
			continue
		}
		uevent := readProperties(filepath.Join(path, "uevent"))
		dev := firstString(readClean(filepath.Join(path, "dev")), majorMinor(uevent["MAJOR"], uevent["MINOR"]))
		blocks[name] = linuxBlock{
			name:     name,
			path:     path,
			resolved: resolved,
			dev:      dev,
			uevent:   uevent,
			udev:     source.udevProperties("b" + dev),
		}
	}
	return blocks
}

func majorMinor(major, minor string) string {
	if major == "" || minor == "" {
		return ""
	}
	return major + ":" + minor
}

func isLinuxPhysicalDisk(source linuxSource, block linuxBlock) bool {
	if block.name == "" || readClean(filepath.Join(block.path, "partition")) != "" {
		return false
	}
	if block.uevent["DEVTYPE"] != "" && block.uevent["DEVTYPE"] != "disk" {
		return false
	}
	normalized := filepath.ToSlash(block.resolved)
	if strings.Contains(normalized, "/devices/virtual/block/") {
		return false
	}
	for _, prefix := range []string{"loop", "ram", "zram", "dm-", "md", "nbd", "rbd", "drbd", "zd"} {
		if strings.HasPrefix(block.name, prefix) {
			return false
		}
	}
	if strings.HasPrefix(block.name, "mmcblk") && (strings.Contains(block.name, "boot") || strings.HasSuffix(block.name, "rpmb")) {
		return false
	}
	return pathWithin(block.resolved, source.sysRoot)
}

func linuxDiskFromBlock(source linuxSource, block linuxBlock, index *uint32) Disk {
	device := filepath.Join(block.path, "device")
	properties := deviceProperties(device, source.sysRoot)
	disk := Disk{
		ID:           filepath.Join(source.devRoot, block.name),
		Index:        index,
		PNPID:        properties["MODALIAS"],
		Vendor:       firstString(readClean(filepath.Join(device, "vendor")), block.udev["ID_VENDOR_FROM_DATABASE"], block.udev["ID_VENDOR"]),
		Model:        firstString(readClean(filepath.Join(device, "model")), block.udev["ID_MODEL_FROM_DATABASE"], block.udev["ID_MODEL"]),
		SerialNumber: firstString(readClean(filepath.Join(device, "serial")), block.udev["ID_SERIAL_SHORT"]),
		BusType:      linuxDiskBus(block, properties),
	}
	disk.CapacityBytes, _ = linuxSectorBytes(filepath.Join(block.path, "size"))
	if value, ok := readUint(filepath.Join(block.path, "queue", "logical_block_size"), 32); ok {
		disk.LogicalSectorSizeBytes = uint32(value)
	}
	if value, ok := readUint(filepath.Join(block.path, "queue", "physical_block_size"), 32); ok {
		disk.PhysicalSectorSizeBytes = uint32(value)
	}
	disk.MediaType = linuxDiskMediaType(block)
	switch strings.ToLower(block.udev["ID_PART_TABLE_TYPE"]) {
	case "gpt", "dos", "mbr":
		disk.PartitionTableType = strings.ToLower(block.udev["ID_PART_TABLE_TYPE"])
		if disk.PartitionTableType == "dos" {
			disk.PartitionTableType = "mbr"
		}
	}
	return disk
}

func linuxSectorBytes(path string) (uint64, bool) {
	sectors, ok := readUint(path, 64)
	if !ok || sectors > math.MaxUint64/512 {
		return 0, false
	}
	return sectors * 512, true
}

func linuxDiskMediaType(block linuxBlock) string {
	if deviceType, ok := readUint(filepath.Join(block.path, "device", "type"), 16); ok && deviceType == 5 {
		return "optical"
	}
	if removable, ok := readUint(filepath.Join(block.path, "removable"), 8); ok && removable == 1 {
		return "removable"
	}
	if rotational, ok := readUint(filepath.Join(block.path, "queue", "rotational"), 8); ok {
		if rotational == 1 {
			return "hdd"
		}
		return "ssd"
	}
	return ""
}

func linuxDiskBus(block linuxBlock, properties map[string]string) string {
	bus := strings.ToLower(firstString(block.udev["ID_BUS"], properties["ID_BUS"]))
	switch bus {
	case "ata", "ieee_1394", "fibre_channel", "iscsi", "mmc", "nvme", "raid", "sas", "sata", "scsi", "sd", "ufs", "usb", "virtio":
		return bus
	}
	path := strings.ToLower(filepath.ToSlash(block.resolved))
	switch {
	case strings.HasPrefix(block.name, "nvme") || strings.Contains(path, "/nvme/"):
		return "nvme"
	case strings.Contains(path, "/usb"):
		return "usb"
	case strings.Contains(path, "/virtio"):
		return "virtio"
	case strings.HasPrefix(block.name, "mmcblk") || strings.Contains(path, "/mmc"):
		return "mmc"
	case strings.Contains(path, "/iscsi"):
		return "iscsi"
	case strings.Contains(path, "/sas"):
		return "sas"
	case strings.Contains(path, "/ata"):
		return "sata"
	case strings.Contains(path, "/scsi") || strings.HasPrefix(block.name, "sd") || strings.HasPrefix(block.name, "sr"):
		return "scsi"
	default:
		return ""
	}
}

func childPartitionNames(disk linuxBlock, blocks map[string]linuxBlock) []string {
	result := make([]string, 0)
	for name, block := range blocks {
		if readClean(filepath.Join(block.path, "partition")) == "" {
			continue
		}
		if filepath.Dir(block.resolved) == disk.resolved {
			result = append(result, name)
		}
	}
	sort.Slice(result, func(i, j int) bool { return naturalLess(result[i], result[j]) })
	return result
}

func attachLinuxVolumes(source linuxSource, blocks map[string]linuxBlock, locations map[string]linuxPartitionLocation, disks []Disk) {
	mounts := readLinuxMounts(source, blocks)
	blockNames := make([]string, 0, len(blocks))
	for name := range blocks {
		blockNames = append(blockNames, name)
	}
	sort.Slice(blockNames, func(i, j int) bool { return naturalLess(blockNames[i], blockNames[j]) })
	for _, name := range blockNames {
		block := blocks[name]
		mount := mounts[name]
		if usage := block.udev["ID_FS_USAGE"]; usage != "" && usage != "filesystem" {
			continue
		}
		if block.udev["ID_FS_TYPE"] == "" && len(mount.points) == 0 {
			continue
		}
		backing := linuxBackingPartitions(name, blocks, locations, make(map[string]bool))
		if len(backing) == 0 {
			continue
		}
		volume := linuxVolumeFromBlock(source, block, mount)
		if volume.ID == "" {
			continue
		}
		for _, location := range backing {
			partition := &disks[location.disk].Partitions[location.partition]
			merged := false
			for index := range partition.Volumes {
				if partition.Volumes[index].ID == volume.ID {
					mergeLinuxVolume(&partition.Volumes[index], volume)
					merged = true
					break
				}
			}
			if !merged {
				partition.Volumes = append(partition.Volumes, volume)
			}
		}
	}
	for diskIndex := range disks {
		for partitionIndex := range disks[diskIndex].Partitions {
			volumes := disks[diskIndex].Partitions[partitionIndex].Volumes
			sort.Slice(volumes, func(i, j int) bool { return volumes[i].ID < volumes[j].ID })
		}
	}
}

func mergeLinuxVolume(target *Volume, source Volume) {
	target.Label = firstString(target.Label, source.Label)
	target.Filesystem = firstString(target.Filesystem, source.Filesystem)
	if target.CapacityBytes == 0 {
		target.CapacityBytes = source.CapacityBytes
	}
	target.MountPoints = append(target.MountPoints, source.MountPoints...)
	sort.Strings(target.MountPoints)
	target.MountPoints = uniqueStrings(target.MountPoints)
}

func linuxVolumeFromBlock(source linuxSource, block linuxBlock, mount linuxMount) Volume {
	volume := Volume{
		ID:          firstString(block.udev["ID_FS_UUID"], mount.source, filepath.Join(source.devRoot, block.name)),
		Label:       block.udev["ID_FS_LABEL"],
		Filesystem:  strings.ToLower(firstString(block.udev["ID_FS_TYPE"], mount.filesystem)),
		MountPoints: append([]string(nil), mount.points...),
	}
	if capacity, err := strconv.ParseUint(block.udev["ID_FS_SIZE"], 10, 64); err == nil {
		volume.CapacityBytes = capacity
	} else {
		volume.CapacityBytes, _ = linuxSectorBytes(filepath.Join(block.path, "size"))
	}
	sort.Strings(volume.MountPoints)
	volume.MountPoints = uniqueStrings(volume.MountPoints)
	return volume
}

func readLinuxMounts(source linuxSource, blocks map[string]linuxBlock) map[string]linuxMount {
	data, err := readLinuxFile(source.proc("self", "mountinfo"), maxLinuxMetadataBytes)
	if err != nil {
		return nil
	}
	byDevice := make(map[string]string)
	for name, block := range blocks {
		if block.dev != "" {
			byDevice[block.dev] = name
		}
	}
	mounts := make(map[string]linuxMount)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if len(fields) < 6 || separator < 0 || separator+2 >= len(fields) {
			continue
		}
		mountSource := unescapeMountInfo(fields[separator+2])
		name := byDevice[fields[2]]
		if name == "" {
			name = linuxBlockNameFromMountSource(source, mountSource, blocks)
		}
		if name == "" {
			continue
		}
		mount := mounts[name]
		mount.filesystem = firstString(mount.filesystem, cleanString(fields[separator+1]))
		mount.source = firstString(mount.source, mountSource)
		mount.points = append(mount.points, unescapeMountInfo(fields[4]))
		mounts[name] = mount
	}
	return mounts
}

func linuxBlockNameFromMountSource(source linuxSource, mountSource string, blocks map[string]linuxBlock) string {
	if !filepath.IsAbs(mountSource) || !pathWithin(mountSource, source.devRoot) {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(mountSource)
	if err != nil {
		resolved = mountSource
	}
	if !pathWithin(resolved, source.devRoot) {
		return ""
	}
	name := filepath.Base(resolved)
	if _, found := blocks[name]; found {
		return name
	}
	return ""
}

func unescapeMountInfo(value string) string {
	var result strings.Builder
	for index := 0; index < len(value); {
		if value[index] == '\\' && index+3 < len(value) {
			if parsed, err := strconv.ParseUint(value[index+1:index+4], 8, 8); err == nil {
				result.WriteByte(byte(parsed))
				index += 4
				continue
			}
		}
		result.WriteByte(value[index])
		index++
	}
	return result.String()
}

func linuxBackingPartitions(name string, blocks map[string]linuxBlock, locations map[string]linuxPartitionLocation, visited map[string]bool) []linuxPartitionLocation {
	if visited[name] {
		return nil
	}
	visited[name] = true
	if location, found := locations[name]; found {
		return []linuxPartitionLocation{location}
	}
	block, found := blocks[name]
	if !found {
		return nil
	}
	if readClean(filepath.Join(block.path, "partition")) != "" {
		parentPath := filepath.Dir(block.resolved)
		parentNames := make([]string, 0)
		for parentName, parent := range blocks {
			if parent.resolved == parentPath {
				parentNames = append(parentNames, parentName)
			}
		}
		sort.Slice(parentNames, func(i, j int) bool { return naturalLess(parentNames[i], parentNames[j]) })
		for _, parentName := range parentNames {
			if result := linuxBackingPartitions(parentName, blocks, locations, visited); len(result) > 0 {
				return result
			}
		}
	}
	result := make([]linuxPartitionLocation, 0)
	for _, slave := range sortedDirNames(filepath.Join(block.path, "slaves")) {
		result = append(result, linuxBackingPartitions(slave, blocks, locations, visited)...)
	}
	return uniqueLocations(result)
}

func uniqueLocations(values []linuxPartitionLocation) []linuxPartitionLocation {
	seen := make(map[linuxPartitionLocation]struct{})
	result := make([]linuxPartitionLocation, 0, len(values))
	for _, value := range values {
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if value == "" || (len(result) > 0 && result[len(result)-1] == value) {
			continue
		}
		result = append(result, value)
	}
	return result
}

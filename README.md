# bigrmm-hwdiscovery

`bigrmm-hwdiscovery` is a small, best-effort Go library developed for our own [remote monitoring and management (RMM) solution](https://www.bit-in.de/rmm). It transparently collects the static hardware identity and configuration data available on a system.

Discovery is performed locally through WMI on Windows, kernel-exposed files and read-only metadata caches on Linux, and Darwin sysctls and native Apple frameworks on macOS. Unavailable data is gracefully omitted, and external programs are never started.

## Usage

```go
package main

import (
	"encoding/json"
	"fmt"

	hwdiscovery "github.com/bit-in-gmbh/bigrmm-hwdiscovery"
)

func main() {
	inventory := hwdiscovery.Discover()
	encoded, _ := json.MarshalIndent(inventory, "", "  ")
	fmt.Println(string(encoded))
}
```

`Discover` has no configuration and returns no error. Reads and queries are local, sequential, and independent. Missing kernel files or WMI classes, unavailable properties, permission failures, and unsupported enrichment are represented by omitted fields rather than errors.

The following example shows every possible JSON field. Actual results omit
zero-valued and unavailable data:

```json
{
  "system": {
    "manufacturer": "Example Corp",
    "model": "RoadRunner 15",
    "family": "Mobile",
    "version": "Rev 2",
    "serial_number": "SYS-123",
    "uuid": "abcdef12-3456-7890-abcd-ef1234567890",
    "sku": "SKU-7",
    "system_type": "x86_64",
    "chassis": {
      "manufacturer": "Example Corp",
      "model": "Shell",
      "serial_number": "CASE-1",
      "asset_tag": "ASSET-9",
      "type": "laptop"
    },
    "baseboard": {
      "manufacturer": "Boards Ltd",
      "product": "Board X",
      "version": "1.2",
      "serial_number": "BOARD-1"
    },
    "firmware": {
      "vendor": "Firmware Inc",
      "version": "2.4.6",
      "release_date": "2026-04-03"
    }
  },
  "memory": {
    "installed_physical_bytes": 34359738368,
    "modules": [
      {
        "bank": "BANK 0",
        "location": "DIMM_A",
        "vendor": "Memory Co",
        "part_number": "PART-A",
        "serial_number": "MEM-A",
        "capacity_bytes": 17179869184,
        "configured_speed_mts": 3200,
        "rated_speed_mts": 3200,
        "memory_type": "ddr4",
        "form_factor": "dimm"
      },
      {
        "bank": "BANK 1",
        "location": "DIMM_B",
        "vendor": "Memory Co",
        "part_number": "PART-B",
        "serial_number": "MEM-B",
        "capacity_bytes": 17179869184,
        "configured_speed_mts": 5200,
        "rated_speed_mts": 5600,
        "memory_type": "ddr5",
        "form_factor": "sodimm"
      }
    ]
  },
  "processors": [
    {
      "id": "CPU0",
      "manufacturer": "Chip Co",
      "model": "FastChip",
      "serial_number": "PROCESSOR-A",
      "architecture": "x86_64",
      "socket": "Socket A",
      "physical_core_count": 8,
      "logical_processor_count": 16,
      "max_clock_mhz": 4200
    },
    {
      "id": "CPU1",
      "manufacturer": "Chip Co",
      "model": "FastChip",
      "serial_number": "PROCESSOR-B",
      "architecture": "x86_64",
      "socket": "Socket B",
      "physical_core_count": 8,
      "logical_processor_count": 16,
      "max_clock_mhz": 4200
    }
  ],
  "disks": [
    {
      "id": "\\\\.\\PHYSICALDRIVE0",
      "index": 0,
      "pnp_id": "PCI\\DISK0",
      "vendor": "Disk Co",
      "model": "Speedy",
      "serial_number": "DISK-A",
      "capacity_bytes": 1000000,
      "logical_sector_size_bytes": 512,
      "physical_sector_size_bytes": 4096,
      "media_type": "ssd",
      "bus_type": "nvme",
      "partition_table_type": "gpt",
      "partitions": [
        {
          "id": "Disk #0, Partition #0",
          "index": 0,
          "size_bytes": 400000,
          "starting_offset_bytes": 1024,
          "volumes": [
            {
              "id": "C:",
              "label": "System",
              "filesystem": "ntfs",
              "capacity_bytes": 400000,
              "mount_points": ["C:\\"]
            }
          ]
        },
        {
          "id": "Disk #0, Partition #1",
          "index": 1,
          "size_bytes": 600000,
          "starting_offset_bytes": 400000,
          "volumes": [
            {
              "id": "D:",
              "label": "Data",
              "filesystem": "ntfs",
              "capacity_bytes": 600000,
              "mount_points": ["D:\\"]
            }
          ]
        }
      ]
    },
    {
      "id": "\\\\.\\PHYSICALDRIVE1",
      "index": 1,
      "pnp_id": "USBSTOR\\DISK1",
      "vendor": "Disk Co",
      "model": "Archive",
      "serial_number": "DISK-B",
      "capacity_bytes": 2000000,
      "logical_sector_size_bytes": 512,
      "physical_sector_size_bytes": 4096,
      "media_type": "hdd",
      "bus_type": "usb",
      "partition_table_type": "mbr",
      "partitions": [
        {
          "id": "Disk #1, Partition #0",
          "index": 0,
          "size_bytes": 2000000,
          "starting_offset_bytes": 1024,
          "volumes": [
            {
              "id": "E:",
              "label": "Archive",
              "filesystem": "exfat",
              "capacity_bytes": 2000000,
              "mount_points": ["E:\\"]
            }
          ]
        }
      ]
    }
  ],
  "network_adapters": [
    {
      "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "name": "Ethernet",
      "model": "Ether 1",
      "vendor": "Net Co",
      "physical_medium": "ethernet",
      "mac_address": "00:11:22:33:44:55",
      "pnp_id": "PCI\\NIC-A"
    },
    {
      "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "name": "Wi-Fi",
      "model": "Wireless 2",
      "vendor": "Net Co",
      "physical_medium": "wireless_lan",
      "mac_address": "00:11:22:AA:BB:CC",
      "pnp_id": "PCI\\NIC-B"
    }
  ],
  "gpus": [
    {
      "id": "PCI\\GPU-A",
      "pnp_id": "PCI\\GPU-A",
      "name": "GPU A",
      "manufacturer": "Graphics Co",
      "video_processor": "Core A"
    },
    {
      "id": "PCI\\GPU-B",
      "pnp_id": "PCI\\GPU-B",
      "name": "GPU B",
      "manufacturer": "Graphics Co",
      "video_processor": "Core B"
    }
  ]
}
```

Byte fields are exact byte counts. Memory speeds are MT/s, maximum processor clocks are MHz, firmware dates use `YYYY-MM-DD`, UUIDs are lowercase, MAC addresses are uppercase colon-separated octets, and normalized enum strings are lowercase. All component collections are sorted deterministically. Zero-valued and unavailable data is omitted from JSON.

## Platform support

| Platform | Architecture | Behavior |
| --- | --- | --- |
| Windows 10/11 | amd64, arm64 | Local WMI hardware discovery |
| Windows Server 2016+ | amd64, arm64 | Local WMI hardware discovery |
| Windows | 386 and other architectures | Compiles; returns an empty inventory |
| Linux | amd64, arm64 | Local procfs, sysfs, DMI/SMBIOS, device-tree, mount, and block-device metadata discovery |
| Linux | Other architectures | Compiles; returns an empty inventory |
| macOS | amd64, arm64 | Local Sysctl, IOKit, CoreFoundation, Disk Arbitration, and System Configuration discovery |

## Windows discovery

No elevation is attempted. Hardware that the current process cannot inspect is omitted. Optional `MSFT_Disk` and `MSFT_PhysicalDisk` data enriches physical disks when the Storage namespace is available; base disks and partitions remain present when it is not.

## Linux discovery

Linux collectors read `/proc` and `/sys`, including DMI/SMBIOS and device-tree data where the kernel exposes them. They may enrich names, filesystem identity, and partition-table information from the existing read-only udev database under `/run/udev/data` and an installed `pci.ids` database. These caches are optional: the library never contacts udev, opens raw block devices, or invokes `dmidecode`, `lsblk`, `blkid`, `lspci`, or another command.

Physical disks, partitions, and both mounted and recognized unmounted filesystems are inventoried. Device-mapper, LVM, encryption, and software-RAID relationships are followed through sysfs so a terminal filesystem is associated with its backing physical partitions; intermediate wrappers are not reported as disks or volumes. Filesystems placed directly on a whole disk cannot be represented by the partition-nested API and are omitted.

Most Linux identity is readable without elevated privileges. Firmware-configured serial numbers and raw SMBIOS processor or DIMM records are commonly root-only; inaccessible values are omitted while the rest of the inventory is retained. Containers see only the procfs/sysfs and mount namespace made available by their runtime.

## macOS discovery

macOS collectors query Darwin sysctls and the in-process CoreFoundation, IOKit, Disk Arbitration, and System Configuration APIs. They inventory platform identity, processor topology, installed memory, optional Intel SMBIOS memory devices, physical storage and partitions, recognized volumes, physical network interfaces, and graphics controllers without invoking `system_profiler`, `ioreg`, `diskutil`, `sysctl`, or another program.

The native framework enrichment is available when cgo is enabled, which is the default for native macOS builds. A macOS build with cgo disabled still compiles and returns the system, processor, and installed-memory information available through sysctl. APFS volumes are associated with a physical partition when IOKit's registry exposes that ancestry; otherwise the physical disk and partition remain present while the volume is omitted.

## Inventory, not monitoring

This module collects hardware identity and configuration. It deliberately does not collect CPU load or current clock, available memory, disk free/used capacity or SMART health, IP addresses/link state/current speed, GPU utilization or temperature, power-on hours, or other transient metrics. Runtime code does not invoke PowerShell, `wmic`, `system_profiler`, `ioreg`, `diskutil`, `sysctl`, `dmidecode`, `lsblk`, `blkid`, `lspci`, shells, or other platform utilities.

## Security and privacy

Inventory may contain serial numbers, UUIDs, MAC addresses, PnP identifiers, asset tags, device paths, and volume identifiers. These values can identify or correlate a device. Treat serialized inventory as sensitive operational data: minimize retention, restrict access, encrypt it in transit and at rest, and obtain any consent required by your policies or applicable law.

Hardwarewerte bleiben ungeprüfte Angaben von Firmware, Treibern und Betriebssystem. Anwendungen müssen Inventartexte bei der Darstellung oder Protokollierung passend zum jeweiligen Ausgabeformat behandeln. Die Bibliothek erhöht keine Rechte und stellt keine Sicherheitsgrenze gegen einen kompromittierten Kernel oder Administrator dar.

Metadatenleser und native Puffer sind begrenzt; übergroße oder ungültige Angaben werden bestmöglich ausgelassen. Go 1.27.3 ist die minimale Buildversion. Änderungen, konkrete Grenzen und tatsächlich ausgeführte Prüfungen stehen im [Sicherheits- und Hardeningbericht vom 2. November 2026](docs/security-hardening-2026-11-02.md).

## Repository version and releases

The root `VERSION` file is the manually maintained repository version. It is
independent of QS, software discovery and the management repositories. This
library has no standalone executable and therefore no binary component version.
`VERSION` starts at `1.3.0`; the existing `v1.3.0` tag is preserved at its original
commit. The current checkout and its unreleased changes are not a replacement
for that tagged release.

Choose the next stable SemVer `X.Y.Z` manually according to the exported Go/JSON
contract, update `VERSION` and `CHANGELOG.md`, and run the documented checks.
Commit related changes together with a Conventional Commit subject. A later
explicit release uses the tag `vX.Y.Z` matching `VERSION`; never move or reuse a
published tag. No automatic bumps, tags or pushes are performed.

QS builds read this version for package provenance alongside the exact source
commit. The library itself is compiled into its caller and is not independently
code-signed; signing and binary artifact reuse belong to the consuming release.

## License and third-party notices

The project is licensed under Apache-2.0. Dependency and design-reference notices are in [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

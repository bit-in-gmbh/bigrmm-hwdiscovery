//go:build linux && (amd64 || arm64)

package hwdiscovery

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLinuxMetadataReadLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata")
	writeFixture(t, path, []byte("12345678"))
	data, err := readLinuxFile(path, 8)
	if err != nil || string(data) != "12345678" {
		t.Fatalf("metadata at limit was not retained: %q, %v", data, err)
	}
	writeFixture(t, path, []byte("123456789"))
	if data, err := readLinuxFile(path, 8); err == nil || data != nil {
		t.Fatalf("oversized metadata was accepted or truncated: %q, %v", data, err)
	}
	// procfs reports a zero length even though it contains readable data.
	if data, err := readLinuxFile("/proc/self/stat", maxLinuxAttributeBytes); err != nil || len(data) == 0 {
		t.Fatalf("kernel metadata with zero reported length was rejected: %v", err)
	}
}

func TestLinuxMetadataRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	pipe := filepath.Join(t.TempDir(), "metadata-pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{pipe, "/dev/zero", t.TempDir()} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				_, err := readLinuxFile(path, 8)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("special file was accepted as hardware metadata")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("reading a special file blocked")
			}
		})
	}
}

func TestLinuxOversizedAttributePreservesIndependentHardware(t *testing.T) {
	source := completeLinuxFixture(t)
	oversized := bytes.Repeat([]byte("x"), maxLinuxAttributeBytes+1)
	writeFixture(t, source.sys("class/dmi/id/product_name"), oversized)
	writeFixture(t, source.sys("firmware/dmi/entries/17-0/raw"), oversized)
	inventory := discoverLinux(source)
	if inventory.System == nil || inventory.System.Model != "" || inventory.System.Manufacturer != "Example Corp" || inventory.Memory == nil || inventory.Memory.InstalledPhysicalBytes != 8<<30 || len(inventory.Memory.Modules) != 1 || len(inventory.Processors) != 1 || len(inventory.Disks) != 1 {
		t.Fatalf("oversized attribute affected independent inventory: %#v", inventory)
	}
}

func TestLinuxOversizedPCIMetadataFallsBack(t *testing.T) {
	root := t.TempDir()
	oversized := filepath.Join(root, "oversized.ids")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxLinuxMetadataBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(root, "pci.ids")
	writeFixture(t, fallback, []byte("1234  Vendor\n\t5678  Model\n"))
	database := loadPCIDatabase([]string{oversized, fallback})
	if vendor, model := database.lookup("0x1234", "0x5678"); vendor != "Vendor" || model != "Model" {
		t.Fatalf("oversized PCI database prevented fallback: %q, %q", vendor, model)
	}
}

func TestLinuxUdevLookupRejectsPathComponents(t *testing.T) {
	source := linuxSource{runRoot: t.TempDir()}
	writeFixture(t, source.run("udev/data/b8:0"), []byte("E:ID_MODEL=Safe\n"))
	writeFixture(t, source.run("payload"), []byte("E:ID_MODEL=Outside\n"))
	if properties := source.udevProperties("b8:0"); properties["ID_MODEL"] != "Safe" {
		t.Fatalf("normal udev key was rejected: %#v", properties)
	}
	for _, name := range []string{"", ".", "..", "../../payload", "b8/../../../payload", "n/../../../payload", "+pci:/../../../payload"} {
		if properties := source.udevProperties(name); properties != nil {
			t.Errorf("udev path component %q was accepted: %#v", name, properties)
		}
	}
}

func TestLinuxMetadataRejectsDeviceLinksOutsideSysRoot(t *testing.T) {
	source := linuxSource{sysRoot: t.TempDir()}
	outside := t.TempDir()
	writeFixture(t, filepath.Join(outside, "uevent"), []byte("MODALIAS=pci:outside\nDEVTYPE=disk\n"))
	link := source.sys("class/block/escaped")
	linkFixture(t, outside, link)
	if properties := deviceProperties(link, source.sysRoot); properties != nil {
		t.Fatalf("device metadata escaped sysfs root: %#v", properties)
	}
	if blocks := scanLinuxBlocks(source); len(blocks) != 0 {
		t.Fatalf("block metadata escaped sysfs root: %#v", blocks)
	}
	inside := source.sys("devices/example")
	writeFixture(t, filepath.Join(inside, "uevent"), []byte("MODALIAS=pci:inside\n"))
	if err := os.MkdirAll(filepath.Join(inside, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if properties := deviceProperties(filepath.Join(inside, "child"), source.sysRoot); properties["MODALIAS"] != "pci:inside" {
		t.Fatalf("valid ancestor metadata was lost: %#v", properties)
	}
}

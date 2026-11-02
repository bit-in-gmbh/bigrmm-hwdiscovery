//go:build darwin && cgo

package hwdiscovery

/*
#cgo LDFLAGS: -framework CoreFoundation -framework IOKit -framework DiskArbitration -framework SystemConfiguration

#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/storage/IOMedia.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Hardware properties are small metadata. Allow up to 1 MiB per property and
// 16 MiB per collector, including terminators. Corrupt or excessive metadata
// must not cause unbounded allocations; complete earlier rows remain usable.
#define HW_MAX_PROPERTY_BYTES (1024 * 1024)
#define HW_MAX_INVENTORY_BYTES (16 * 1024 * 1024)

typedef struct {
	char *data;
	size_t length;
	size_t capacity;
	size_t row_start;
	int failed;
} hw_buffer;

typedef struct {
	void *data;
	size_t length;
} hw_blob;

static int hw_buffer_reserve(hw_buffer *buffer, size_t extra) {
	if (buffer->failed) {
		return 0;
	}
	if (buffer->length >= HW_MAX_INVENTORY_BYTES || extra > HW_MAX_INVENTORY_BYTES - buffer->length - 1) {
		buffer->failed = 1;
		buffer->length = buffer->row_start;
		if (buffer->data != NULL) {
			buffer->data[buffer->length] = '\0';
		}
		return 0;
	}
	size_t needed = buffer->length + extra + 1;
	if (needed <= buffer->capacity) {
		return 1;
	}
	size_t capacity = buffer->capacity == 0 ? 1024 : buffer->capacity;
	while (capacity < needed) {
		if (capacity > SIZE_MAX / 2) {
			capacity = needed;
			break;
		}
		capacity *= 2;
	}
	char *data = (char *)realloc(buffer->data, capacity);
	if (data == NULL) {
		buffer->failed = 1;
		buffer->length = buffer->row_start;
		if (buffer->data != NULL) {
			buffer->data[buffer->length] = '\0';
		}
		return 0;
	}
	buffer->data = data;
	buffer->capacity = capacity;
	return 1;
}

static void hw_buffer_append_bytes(hw_buffer *buffer, const char *value, size_t length) {
	if (value == NULL || length == 0 || !hw_buffer_reserve(buffer, length)) {
		return;
	}
	memcpy(buffer->data + buffer->length, value, length);
	buffer->length += length;
	buffer->data[buffer->length] = '\0';
}

static void hw_buffer_append(hw_buffer *buffer, const char *value) {
	if (value != NULL) {
		hw_buffer_append_bytes(buffer, value, strlen(value));
	}
}

static void hw_buffer_append_clean(hw_buffer *buffer, const char *value) {
	if (value == NULL || buffer->failed) {
		return;
	}
	for (const unsigned char *cursor = (const unsigned char *)value; *cursor != 0 && !buffer->failed; cursor++) {
		char character = (char)*cursor;
		if (character == '\t' || character == '\r' || character == '\n' || character == '\0') {
			character = ' ';
		}
		hw_buffer_append_bytes(buffer, &character, 1);
	}
}

static void hw_row_start(hw_buffer *buffer, const char *kind) {
	if (buffer->failed) {
		return;
	}
	buffer->row_start = buffer->length;
	if (buffer->length != 0) {
		hw_buffer_append(buffer, "\n");
	}
	hw_buffer_append_clean(buffer, kind);
}

static void hw_row_field(hw_buffer *buffer, const char *key, const char *value) {
	if (key == NULL || value == NULL || value[0] == '\0') {
		return;
	}
	hw_buffer_append(buffer, "\t");
	hw_buffer_append_clean(buffer, key);
	hw_buffer_append(buffer, "\t");
	hw_buffer_append_clean(buffer, value);
}

static void hw_row_uint64(hw_buffer *buffer, const char *key, uint64_t value) {
	if (value == 0) {
		return;
	}
	char text[32];
	snprintf(text, sizeof(text), "%llu", (unsigned long long)value);
	hw_row_field(buffer, key, text);
}

static char *hw_buffer_finish(hw_buffer *buffer) {
	if (buffer->data == NULL) {
		buffer->data = (char *)calloc(1, 1);
	}
	return buffer->data;
}

static char *hw_cf_string(CFTypeRef value) {
	if (value == NULL) {
		return NULL;
	}
	CFTypeID type = CFGetTypeID(value);
	CFStringRef string = NULL;
	int releaseString = 0;
	if (type == CFStringGetTypeID()) {
		string = (CFStringRef)value;
	} else if (type == CFURLGetTypeID()) {
		string = CFURLCopyFileSystemPath((CFURLRef)value, kCFURLPOSIXPathStyle);
		releaseString = 1;
	} else if (type == CFUUIDGetTypeID()) {
		string = CFUUIDCreateString(kCFAllocatorDefault, (CFUUIDRef)value);
		releaseString = 1;
	} else if (type == CFBooleanGetTypeID()) {
		return strdup(CFBooleanGetValue((CFBooleanRef)value) ? "true" : "false");
	} else if (type == CFNumberGetTypeID()) {
		long long number = 0;
		if (CFNumberGetValue((CFNumberRef)value, kCFNumberLongLongType, &number)) {
			char text[32];
			snprintf(text, sizeof(text), "%lld", number);
			return strdup(text);
		}
		return NULL;
	} else if (type == CFDataGetTypeID()) {
		CFDataRef data = (CFDataRef)value;
		CFIndex length = CFDataGetLength(data);
		if (length < 0 || length > HW_MAX_PROPERTY_BYTES) {
			return NULL;
		}
		const UInt8 *bytes = CFDataGetBytePtr(data);
		while (length > 0 && bytes[length - 1] == 0) {
			length--;
		}
		int printable = length > 0;
		for (CFIndex index = 0; index < length; index++) {
			if (bytes[index] == 0 || bytes[index] == '\t' || bytes[index] == '\r' || bytes[index] == '\n' || bytes[index] < 0x20) {
				printable = 0;
				break;
			}
		}
		if (printable) {
			string = CFStringCreateWithBytes(kCFAllocatorDefault, bytes, length, kCFStringEncodingUTF8, false);
			if (string != NULL) {
				releaseString = 1;
			}
		}
		if (string == NULL && length > 0 && length <= 8) {
			uint64_t number = 0;
			for (CFIndex index = 0; index < length; index++) {
				number |= ((uint64_t)bytes[index]) << (8 * index);
			}
			char text[32];
			snprintf(text, sizeof(text), "%llu", (unsigned long long)number);
			return strdup(text);
		}
	}
	if (string == NULL) {
		return NULL;
	}
	CFIndex length = CFStringGetLength(string);
	CFIndex maximum = length < 0 || length > HW_MAX_PROPERTY_BYTES ? -1 :
		CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8);
	if (maximum < 0 || maximum >= HW_MAX_PROPERTY_BYTES) {
		if (releaseString) {
			CFRelease(string);
		}
		return NULL;
	}
	maximum++;
	char *result = (char *)malloc((size_t)maximum);
	if (result == NULL || !CFStringGetCString(string, result, maximum, kCFStringEncodingUTF8)) {
		free(result);
		result = NULL;
	}
	if (releaseString) {
		CFRelease(string);
	}
	return result;
}

static uint64_t hw_cf_uint64(CFTypeRef value, int *ok) {
	*ok = 0;
	if (value == NULL) {
		return 0;
	}
	CFTypeID type = CFGetTypeID(value);
	if (type == CFNumberGetTypeID()) {
		int64_t number = 0;
		if (CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &number) && number >= 0) {
			*ok = 1;
			return number;
		}
	} else if (type == CFBooleanGetTypeID()) {
		*ok = 1;
		return CFBooleanGetValue((CFBooleanRef)value) ? 1 : 0;
	} else if (type == CFDataGetTypeID()) {
		CFDataRef data = (CFDataRef)value;
		CFIndex length = CFDataGetLength(data);
		if (length > 0 && length <= 8) {
			const UInt8 *bytes = CFDataGetBytePtr(data);
			uint64_t number = 0;
			for (CFIndex index = 0; index < length; index++) {
				number |= ((uint64_t)bytes[index]) << (8 * index);
			}
			*ok = 1;
			return number;
		}
	} else if (type == CFStringGetTypeID()) {
		char *text = hw_cf_string(value);
		if (text != NULL) {
			char *end = NULL;
			errno = 0;
			uint64_t number = strtoull(text, &end, 0);
			if (isdigit((unsigned char)text[0]) && errno != ERANGE && end != text && *end == '\0') {
				*ok = 1;
			}
			free(text);
			return number;
		}
	}
	return 0;
}

static CFTypeRef hw_copy_property(io_registry_entry_t entry, const char *key, int searchParents) {
	if (entry == IO_OBJECT_NULL || key == NULL) {
		return NULL;
	}
	CFStringRef propertyKey = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
	if (propertyKey == NULL) {
		return NULL;
	}
	CFTypeRef value;
	if (searchParents) {
		value = IORegistryEntrySearchCFProperty(entry, kIOServicePlane, propertyKey, kCFAllocatorDefault,
			kIORegistryIterateRecursively | kIORegistryIterateParents);
	} else {
		value = IORegistryEntryCreateCFProperty(entry, propertyKey, kCFAllocatorDefault, 0);
	}
	CFRelease(propertyKey);
	return value;
}

static CFTypeRef hw_copy_nested_property(io_registry_entry_t entry, const char *dictionaryKey, const char *key) {
	CFTypeRef dictionaryValue = hw_copy_property(entry, dictionaryKey, 1);
	if (dictionaryValue == NULL || CFGetTypeID(dictionaryValue) != CFDictionaryGetTypeID()) {
		if (dictionaryValue != NULL) {
			CFRelease(dictionaryValue);
		}
		return NULL;
	}
	CFStringRef propertyKey = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
	CFTypeRef value = propertyKey == NULL ? NULL : CFDictionaryGetValue((CFDictionaryRef)dictionaryValue, propertyKey);
	if (value != NULL) {
		CFRetain(value);
	}
	if (propertyKey != NULL) {
		CFRelease(propertyKey);
	}
	CFRelease(dictionaryValue);
	return value;
}

static void hw_row_cf(hw_buffer *buffer, const char *key, CFTypeRef value) {
	char *text = hw_cf_string(value);
	if (text != NULL) {
		hw_row_field(buffer, key, text);
		free(text);
	}
}

static void hw_row_property(hw_buffer *buffer, const char *outputKey, io_registry_entry_t entry, const char *propertyKey, int searchParents) {
	CFTypeRef value = hw_copy_property(entry, propertyKey, searchParents);
	if (value != NULL) {
		hw_row_cf(buffer, outputKey, value);
		CFRelease(value);
	}
}

static void hw_row_nested_property(hw_buffer *buffer, const char *outputKey, io_registry_entry_t entry, const char *dictionaryKey, const char *propertyKey) {
	CFTypeRef value = hw_copy_nested_property(entry, dictionaryKey, propertyKey);
	if (value != NULL) {
		hw_row_cf(buffer, outputKey, value);
		CFRelease(value);
	}
}

static int hw_contains_case_insensitive(const char *text, const char *needle) {
	if (text == NULL || needle == NULL || needle[0] == '\0') {
		return 0;
	}
	size_t needleLength = strlen(needle);
	for (; *text != '\0'; text++) {
		size_t index = 0;
		while (index < needleLength && text[index] != '\0' &&
			tolower((unsigned char)text[index]) == tolower((unsigned char)needle[index])) {
			index++;
		}
		if (index == needleLength) {
			return 1;
		}
	}
	return 0;
}

static int hw_registry_path(io_registry_entry_t entry, char *path, size_t length) {
	if (entry == IO_OBJECT_NULL || path == NULL || length == 0) {
		return 0;
	}
	path[0] = '\0';
	return IORegistryEntryGetPath(entry, kIOServicePlane, path) == KERN_SUCCESS && path[0] != '\0';
}

static char *hw_system(void) {
	hw_buffer buffer = {0};
	hw_row_start(&buffer, "system");
	io_service_t platform = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
	if (platform != IO_OBJECT_NULL) {
		hw_row_property(&buffer, "manufacturer", platform, "manufacturer", 0);
		hw_row_property(&buffer, "model", platform, "model", 0);
		hw_row_property(&buffer, "product_name", platform, "product-name", 0);
		hw_row_property(&buffer, "model_number", platform, "model-number", 0);
		hw_row_property(&buffer, "serial_number", platform, "IOPlatformSerialNumber", 0);
		hw_row_property(&buffer, "uuid", platform, "IOPlatformUUID", 0);
		hw_row_property(&buffer, "target_type", platform, "target-type", 0);
		hw_row_property(&buffer, "board_id", platform, "board-id", 0);
		hw_row_property(&buffer, "board_manufacturer", platform, "board-manufacturer", 0);
		hw_row_property(&buffer, "board_version", platform, "board-revision", 0);
		hw_row_property(&buffer, "board_serial", platform, "board-serial-number", 0);
		hw_row_property(&buffer, "chassis_type", platform, "chassis-type", 0);
		hw_row_property(&buffer, "chassis_model", platform, "chassis-model", 0);
		hw_row_property(&buffer, "chassis_serial", platform, "chassis-serial-number", 0);
		hw_row_property(&buffer, "asset_tag", platform, "asset-tag", 0);
		hw_row_property(&buffer, "firmware_vendor", platform, "firmware-vendor", 0);
		hw_row_property(&buffer, "firmware_version", platform, "firmware-version", 0);
		hw_row_property(&buffer, "firmware_version", platform, "rom-version", 0);
		hw_row_property(&buffer, "firmware_date", platform, "firmware-date", 0);
		IOObjectRelease(platform);
	}
	io_registry_entry_t rom = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/rom");
	if (rom != IO_OBJECT_NULL) {
		hw_row_property(&buffer, "firmware_vendor", rom, "vendor", 0);
		hw_row_property(&buffer, "firmware_version", rom, "version", 0);
		hw_row_property(&buffer, "firmware_version", rom, "rom-version", 0);
		hw_row_property(&buffer, "firmware_date", rom, "release-date", 0);
		IOObjectRelease(rom);
	}
	return hw_buffer_finish(&buffer);
}

static int hw_media_is_whole(io_registry_entry_t media) {
	CFTypeRef value = hw_copy_property(media, "Whole", 0);
	int result = 0;
	if (value != NULL) {
		if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
			result = CFBooleanGetValue((CFBooleanRef)value);
		} else {
			int ok = 0;
			result = hw_cf_uint64(value, &ok) != 0 && ok;
		}
		CFRelease(value);
	}
	return result;
}

static char *hw_media_bsd_name(io_registry_entry_t media) {
	CFTypeRef value = hw_copy_property(media, "BSD Name", 0);
	char *name = hw_cf_string(value);
	if (value != NULL) {
		CFRelease(value);
	}
	return name;
}

static int hw_path_is_virtual(const char *path) {
	const char *tokens[] = {"AppleAPFS", "CoreStorage", "DiskImage", "IOHDIX", "Virtual", "RAMDisk"};
	for (size_t index = 0; index < sizeof(tokens) / sizeof(tokens[0]); index++) {
		if (hw_contains_case_insensitive(path, tokens[index])) {
			return 1;
		}
	}
	return 0;
}

static int hw_media_is_physical(io_registry_entry_t media, const char *path) {
	if (hw_path_is_virtual(path)) {
		return 0;
	}
	io_registry_entry_t current = media;
	IOObjectRetain(current);
	int found = 0;
	for (int depth = 0; depth < 32; depth++) {
		if (IOObjectConformsTo(current, "IOBlockStorageDevice")) {
			found = 1;
			break;
		}
		io_registry_entry_t parent = IO_OBJECT_NULL;
		if (IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent) != KERN_SUCCESS) {
			break;
		}
		IOObjectRelease(current);
		current = parent;
	}
	IOObjectRelease(current);
	return found;
}

static uint64_t hw_property_uint64(io_registry_entry_t entry, const char *key, int searchParents) {
	CFTypeRef value = hw_copy_property(entry, key, searchParents);
	int ok = 0;
	uint64_t result = hw_cf_uint64(value, &ok);
	if (value != NULL) {
		CFRelease(value);
	}
	return ok ? result : 0;
}

static void hw_row_da_value(hw_buffer *buffer, const char *key, CFDictionaryRef description, CFStringRef descriptionKey) {
	if (description == NULL || descriptionKey == NULL) {
		return;
	}
	hw_row_cf(buffer, key, CFDictionaryGetValue(description, descriptionKey));
}

static CFDictionaryRef hw_disk_description(DASessionRef session, io_service_t media) {
	if (session == NULL || media == IO_OBJECT_NULL) {
		return NULL;
	}
	DADiskRef disk = DADiskCreateFromIOMedia(kCFAllocatorDefault, session, media);
	if (disk == NULL) {
		return NULL;
	}
	CFDictionaryRef description = DADiskCopyDescription(disk);
	CFRelease(disk);
	return description;
}

static const char *hw_partition_scheme(io_registry_entry_t media) {
	io_iterator_t iterator = IO_OBJECT_NULL;
	if (IORegistryEntryCreateIterator(media, kIOServicePlane, kIORegistryIterateRecursively, &iterator) != KERN_SUCCESS) {
		return NULL;
	}
	const char *scheme = NULL;
	io_registry_entry_t child;
	while ((child = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
		if (IOObjectConformsTo(child, "IOGUIDPartitionScheme")) {
			scheme = "gpt";
		} else if (scheme == NULL && IOObjectConformsTo(child, "IOFDiskPartitionScheme")) {
			scheme = "mbr";
		} else if (scheme == NULL && IOObjectConformsTo(child, "IOApplePartitionScheme")) {
			scheme = "apm";
		}
		IOObjectRelease(child);
		if (scheme != NULL && strcmp(scheme, "gpt") == 0) {
			break;
		}
	}
	IOObjectRelease(iterator);
	return scheme;
}

static int hw_partition_belongs_to_disk(const char *disk, const char *partition) {
	if (disk == NULL || partition == NULL) {
		return 0;
	}
	size_t length = strlen(disk);
	if (strncmp(disk, partition, length) != 0 || partition[length] != 's') {
		return 0;
	}
	const char *suffix = partition + length + 1;
	if (!isdigit((unsigned char)*suffix)) {
		return 0;
	}
	for (; *suffix != '\0'; suffix++) {
		if (!isdigit((unsigned char)*suffix)) {
			return 0;
		}
	}
	return 1;
}

static unsigned long hw_disk_index(const char *name) {
	if (name == NULL || strncmp(name, "disk", 4) != 0) {
		return 0;
	}
	return strtoul(name + 4, NULL, 10);
}

static unsigned long hw_partition_index(const char *name) {
	if (name == NULL) {
		return 0;
	}
	const char *separator = strrchr(name, 's');
	return separator == NULL ? 0 : strtoul(separator + 1, NULL, 10);
}

static void hw_append_volume(hw_buffer *buffer, DASessionRef session, io_service_t media, const char *partitionID) {
	CFDictionaryRef description = hw_disk_description(session, media);
	if (description == NULL) {
		return;
	}
	CFTypeRef kind = CFDictionaryGetValue(description, kDADiskDescriptionVolumeKindKey);
	CFTypeRef name = CFDictionaryGetValue(description, kDADiskDescriptionVolumeNameKey);
	CFTypeRef path = CFDictionaryGetValue(description, kDADiskDescriptionVolumePathKey);
	if (kind != NULL || name != NULL || path != NULL) {
		hw_row_start(buffer, "volume");
		hw_row_field(buffer, "parent", partitionID);
		hw_row_da_value(buffer, "id", description, kDADiskDescriptionMediaUUIDKey);
		hw_row_da_value(buffer, "id", description, kDADiskDescriptionVolumeUUIDKey);
		hw_row_da_value(buffer, "label", description, kDADiskDescriptionVolumeNameKey);
		hw_row_da_value(buffer, "filesystem", description, kDADiskDescriptionVolumeKindKey);
		hw_row_da_value(buffer, "capacity_bytes", description, kDADiskDescriptionMediaSizeKey);
		hw_row_da_value(buffer, "mount_point", description, kDADiskDescriptionVolumePathKey);
	}
	CFRelease(description);
}

static char *hw_physical_partition_ancestor(io_registry_entry_t entry, const char *diskBSD) {
	io_registry_entry_t current = entry;
	IOObjectRetain(current);
	char *result = NULL;
	for (int depth = 0; depth < 64; depth++) {
		if (IOObjectConformsTo(current, kIOMediaClass) && !hw_media_is_whole(current)) {
			char *bsd = hw_media_bsd_name(current);
			if (hw_partition_belongs_to_disk(diskBSD, bsd)) {
				result = bsd;
				break;
			}
			free(bsd);
		}
		io_registry_entry_t parent = IO_OBJECT_NULL;
		if (IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent) != KERN_SUCCESS) {
			break;
		}
		IOObjectRelease(current);
		current = parent;
	}
	IOObjectRelease(current);
	return result;
}

static char *hw_storage(void) {
	hw_buffer buffer = {0};
	DASessionRef session = DASessionCreate(kCFAllocatorDefault);
	io_iterator_t iterator = IO_OBJECT_NULL;
	CFMutableDictionaryRef matching = IOServiceMatching(kIOMediaClass);
	if (matching == NULL || IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) != KERN_SUCCESS) {
		if (session != NULL) {
			CFRelease(session);
		}
		return hw_buffer_finish(&buffer);
	}
	io_service_t media;
	while ((media = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
		if (!hw_media_is_whole(media)) {
			IOObjectRelease(media);
			continue;
		}
		char path[4096];
		char *bsd = hw_media_bsd_name(media);
		if (bsd == NULL || !hw_registry_path(media, path, sizeof(path)) || !hw_media_is_physical(media, path)) {
			free(bsd);
			IOObjectRelease(media);
			continue;
		}

		hw_row_start(&buffer, "disk");
		hw_row_field(&buffer, "id", bsd);
		char index[32];
		snprintf(index, sizeof(index), "%lu", hw_disk_index(bsd));
		hw_row_field(&buffer, "index", index);
		hw_row_field(&buffer, "pnp_id", path);
		hw_row_nested_property(&buffer, "vendor", media, "Device Characteristics", "Vendor Name");
		hw_row_nested_property(&buffer, "model", media, "Device Characteristics", "Product Name");
		hw_row_nested_property(&buffer, "serial_number", media, "Device Characteristics", "Serial Number");
		hw_row_nested_property(&buffer, "media_type", media, "Device Characteristics", "Medium Type");
		hw_row_nested_property(&buffer, "bus_type", media, "Protocol Characteristics", "Physical Interconnect");
		hw_row_uint64(&buffer, "capacity_bytes", hw_property_uint64(media, "Size", 0));
		hw_row_uint64(&buffer, "logical_sector_size_bytes", hw_property_uint64(media, "Preferred Block Size", 0));
		hw_row_uint64(&buffer, "physical_sector_size_bytes", hw_property_uint64(media, "Physical Block Size", 1));
		hw_row_property(&buffer, "partition_table_type", media, "Content", 0);
		hw_row_field(&buffer, "partition_table_type", hw_partition_scheme(media));

		CFDictionaryRef diskDescription = hw_disk_description(session, media);
		if (diskDescription != NULL) {
			hw_row_da_value(&buffer, "vendor", diskDescription, kDADiskDescriptionDeviceVendorKey);
			hw_row_da_value(&buffer, "model", diskDescription, kDADiskDescriptionDeviceModelKey);
			hw_row_da_value(&buffer, "bus_type", diskDescription, kDADiskDescriptionDeviceProtocolKey);
			hw_row_da_value(&buffer, "capacity_bytes", diskDescription, kDADiskDescriptionMediaSizeKey);
			hw_row_da_value(&buffer, "logical_sector_size_bytes", diskDescription, kDADiskDescriptionMediaBlockSizeKey);
			CFRelease(diskDescription);
		}

		io_iterator_t children = IO_OBJECT_NULL;
		if (IORegistryEntryCreateIterator(media, kIOServicePlane, kIORegistryIterateRecursively, &children) == KERN_SUCCESS) {
			io_registry_entry_t child;
			while ((child = IOIteratorNext(children)) != IO_OBJECT_NULL) {
				if (!IOObjectConformsTo(child, kIOMediaClass) || hw_media_is_whole(child)) {
					IOObjectRelease(child);
					continue;
				}
				char *partitionBSD = hw_media_bsd_name(child);
				if (!hw_partition_belongs_to_disk(bsd, partitionBSD)) {
					char *physicalPartition = hw_physical_partition_ancestor(child, bsd);
					if (physicalPartition != NULL) {
						hw_append_volume(&buffer, session, child, physicalPartition);
						free(physicalPartition);
					}
					free(partitionBSD);
					IOObjectRelease(child);
					continue;
				}
				if (hw_property_uint64(child, "Base", 0) == 0 && hw_partition_index(partitionBSD) == 0) {
					free(partitionBSD);
					IOObjectRelease(child);
					continue;
				}
				hw_row_start(&buffer, "partition");
				hw_row_field(&buffer, "parent", bsd);
				hw_row_field(&buffer, "id", partitionBSD);
				char partitionIndex[32];
				snprintf(partitionIndex, sizeof(partitionIndex), "%lu", hw_partition_index(partitionBSD));
				hw_row_field(&buffer, "index", partitionIndex);
				hw_row_uint64(&buffer, "size_bytes", hw_property_uint64(child, "Size", 0));
				hw_row_uint64(&buffer, "starting_offset_bytes", hw_property_uint64(child, "Base", 0));
				hw_append_volume(&buffer, session, child, partitionBSD);
				free(partitionBSD);
				IOObjectRelease(child);
			}
			IOObjectRelease(children);
		}
		free(bsd);
		IOObjectRelease(media);
	}
	IOObjectRelease(iterator);
	if (session != NULL) {
		CFRelease(session);
	}
	return hw_buffer_finish(&buffer);
}

static int hw_copy_mac(io_registry_entry_t entry, UInt8 output[6]) {
	const char *keys[] = {"IOMACAddress", "IO80211HardwareAddress", "local-mac-address", "mac-address"};
	for (size_t index = 0; index < sizeof(keys) / sizeof(keys[0]); index++) {
		CFTypeRef value = hw_copy_property(entry, keys[index], 1);
		if (value != NULL && CFGetTypeID(value) == CFDataGetTypeID() && CFDataGetLength((CFDataRef)value) == 6) {
			memcpy(output, CFDataGetBytePtr((CFDataRef)value), 6);
			CFRelease(value);
			return 1;
		}
		if (value != NULL) {
			CFRelease(value);
		}
	}
	return 0;
}

static int hw_network_path_is_virtual(const char *path, const char *bsd) {
	const char *tokens[] = {"AWDL", "LLW", "Loopback", "Tunnel", "Bridge", "Bond", "VLAN", "Virtual", "VMNet"};
	if (bsd == NULL || strncmp(bsd, "en", 2) != 0 || !isdigit((unsigned char)bsd[2])) {
		return 1;
	}
	for (size_t index = 0; index < sizeof(tokens) / sizeof(tokens[0]); index++) {
		if (hw_contains_case_insensitive(path, tokens[index])) {
			return 1;
		}
	}
	return 0;
}

static void hw_collect_network_class(hw_buffer *buffer, const char *className) {
	io_iterator_t iterator = IO_OBJECT_NULL;
	CFMutableDictionaryRef matching = IOServiceMatching(className);
	if (matching == NULL || IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) != KERN_SUCCESS) {
		return;
	}
	io_service_t interface;
	while ((interface = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
		char *bsd = hw_media_bsd_name(interface);
		char path[4096];
		UInt8 mac[6];
		if (bsd == NULL || !hw_registry_path(interface, path, sizeof(path)) || hw_network_path_is_virtual(path, bsd) || !hw_copy_mac(interface, mac)) {
			free(bsd);
			IOObjectRelease(interface);
			continue;
		}
		int allZero = 1;
		int allFF = 1;
		for (int index = 0; index < 6; index++) {
			allZero = allZero && mac[index] == 0;
			allFF = allFF && mac[index] == 0xff;
		}
		if (allZero || allFF) {
			free(bsd);
			IOObjectRelease(interface);
			continue;
		}

		hw_row_start(buffer, "network");
		hw_row_field(buffer, "id", bsd);
		hw_row_field(buffer, "name", bsd);
		hw_row_field(buffer, "pnp_id", path);
		char macText[18];
		snprintf(macText, sizeof(macText), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		hw_row_field(buffer, "mac_address", macText);
		hw_row_nested_property(buffer, "vendor", interface, "Device Characteristics", "Vendor Name");
		hw_row_nested_property(buffer, "model", interface, "Device Characteristics", "Product Name");
		hw_row_property(buffer, "vendor", interface, "manufacturer", 0);
		hw_row_property(buffer, "model", interface, "model", 0);
		uint64_t vendorID = hw_property_uint64(interface, "vendor-id", 1);
		hw_row_uint64(buffer, "vendor_id", vendorID);
		if (hw_contains_case_insensitive(path, "80211") || hw_contains_case_insensitive(path, "WiFi") ||
			hw_contains_case_insensitive(path, "WLAN") || hw_contains_case_insensitive(path, "AirPort")) {
			hw_row_field(buffer, "physical_medium", "wireless_lan");
		} else {
			hw_row_field(buffer, "physical_medium", "ethernet");
		}
		free(bsd);
		IOObjectRelease(interface);
	}
	IOObjectRelease(iterator);

}

static void hw_collect_sc_network(hw_buffer *buffer) {
	CFArrayRef interfaces = SCNetworkInterfaceCopyAll();
	if (interfaces == NULL) {
		return;
	}
	CFIndex count = CFArrayGetCount(interfaces);
	for (CFIndex index = 0; index < count; index++) {
		SCNetworkInterfaceRef interface = (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(interfaces, index);
		CFStringRef type = SCNetworkInterfaceGetInterfaceType(interface);
		int wireless = type != NULL && CFEqual(type, kSCNetworkInterfaceTypeIEEE80211);
		if (!wireless && (type == NULL || !CFEqual(type, kSCNetworkInterfaceTypeEthernet))) {
			continue;
		}
		CFStringRef bsd = SCNetworkInterfaceGetBSDName(interface);
		CFStringRef mac = SCNetworkInterfaceGetHardwareAddressString(interface);
		if (bsd == NULL || mac == NULL) {
			continue;
		}
		hw_row_start(buffer, "network");
		hw_row_cf(buffer, "id", bsd);
		CFStringRef name = SCNetworkInterfaceGetLocalizedDisplayName(interface);
		if (name != NULL) {
			hw_row_cf(buffer, "name", name);
		} else {
			hw_row_cf(buffer, "name", bsd);
		}
		hw_row_cf(buffer, "mac_address", mac);
		hw_row_field(buffer, "physical_medium", wireless ? "wireless_lan" : "ethernet");
	}
	CFRelease(interfaces);
}

static char *hw_network(void) {
	hw_buffer buffer = {0};
	hw_collect_network_class(&buffer, "IONetworkInterface");
	hw_collect_network_class(&buffer, "IO80211Interface");
	hw_collect_sc_network(&buffer);
	return hw_buffer_finish(&buffer);
}

static io_registry_entry_t hw_find_pci_ancestor(io_registry_entry_t entry) {
	io_registry_entry_t current = entry;
	IOObjectRetain(current);
	for (int depth = 0; depth < 32; depth++) {
		if (IOObjectConformsTo(current, "IOPCIDevice")) {
			return current;
		}
		io_registry_entry_t parent = IO_OBJECT_NULL;
		if (IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent) != KERN_SUCCESS) {
			break;
		}
		IOObjectRelease(current);
		current = parent;
	}
	IOObjectRelease(current);
	return IO_OBJECT_NULL;
}

static void hw_gpu_row(hw_buffer *buffer, io_registry_entry_t service, int requireDisplayClass) {
	io_registry_entry_t pci = hw_find_pci_ancestor(service);
	io_registry_entry_t base = pci != IO_OBJECT_NULL ? pci : service;
	if (pci == IO_OBJECT_NULL) {
		IOObjectRetain(base);
	}
	if (requireDisplayClass) {
		uint64_t classCode = hw_property_uint64(base, "class-code", 0);
		if (((classCode >> 16) & 0xff) != 0x03) {
			IOObjectRelease(base);
			return;
		}
	}
	char path[4096];
	if (!hw_registry_path(base, path, sizeof(path))) {
		IOObjectRelease(base);
		return;
	}
	char serviceName[256] = {0};
	IORegistryEntryGetName(service, serviceName);

	hw_row_start(buffer, "gpu");
	hw_row_field(buffer, "id", path);
	hw_row_field(buffer, "pnp_id", path);
	if (serviceName[0] != '\0') {
		hw_row_field(buffer, "video_processor", serviceName);
		hw_row_field(buffer, "name", serviceName);
	}
	hw_row_property(buffer, "name", base, "model", 0);
	hw_row_property(buffer, "manufacturer", base, "vendor-name", 0);
	hw_row_property(buffer, "manufacturer", base, "manufacturer", 0);
	hw_row_uint64(buffer, "vendor_id", hw_property_uint64(base, "vendor-id", 1));
	if (pci == IO_OBJECT_NULL && (hw_contains_case_insensitive(path, "AppleARM") || hw_contains_case_insensitive(path, "/sgx@"))) {
		hw_row_field(buffer, "manufacturer", "Apple Inc.");
	}
	IOObjectRelease(base);
}

static void hw_collect_gpu_class(hw_buffer *buffer, const char *className, int requireDisplayClass) {
	io_iterator_t iterator = IO_OBJECT_NULL;
	CFMutableDictionaryRef matching = IOServiceMatching(className);
	if (matching == NULL || IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator) != KERN_SUCCESS) {
		return;
	}
	io_service_t service;
	while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
		hw_gpu_row(buffer, service, requireDisplayClass);
		IOObjectRelease(service);
	}
	IOObjectRelease(iterator);
}

static char *hw_gpus(void) {
	hw_buffer buffer = {0};
	hw_collect_gpu_class(&buffer, "IOPCIDevice", 1);
	hw_collect_gpu_class(&buffer, "IOAccelerator", 0);
	return hw_buffer_finish(&buffer);
}

static hw_blob hw_smbios(void) {
	hw_blob result = {0};
	io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleSMBIOS"));
	if (service == IO_OBJECT_NULL) {
		return result;
	}
	const char *keys[] = {"SMBIOS", "SMBIOS Table", "DMI"};
	for (size_t index = 0; index < sizeof(keys) / sizeof(keys[0]); index++) {
		CFTypeRef value = hw_copy_property(service, keys[index], 0);
		if (value != NULL && CFGetTypeID(value) == CFDataGetTypeID()) {
			CFIndex length = CFDataGetLength((CFDataRef)value);
			if (length > 0 && length <= 16 * 1024 * 1024) {
				result.data = malloc((size_t)length);
				if (result.data != NULL) {
					memcpy(result.data, CFDataGetBytePtr((CFDataRef)value), (size_t)length);
					result.length = (size_t)length;
				}
			}
		}
		if (value != NULL) {
			CFRelease(value);
		}
		if (result.data != NULL) {
			break;
		}
	}
	IOObjectRelease(service);
	return result;
}
*/
import "C"

import (
	"strings"
	"unsafe"
)

func readDarwinNativeInventory() darwinNativeInventory {
	result := darwinNativeInventory{}
	if records := darwinRecordsFromC(C.hw_system()); len(records) > 0 {
		result.system = records[0]
	}
	result.storage = darwinRecordsFromC(C.hw_storage())
	result.network = darwinRecordsFromC(C.hw_network())
	result.gpus = darwinRecordsFromC(C.hw_gpus())

	blob := C.hw_smbios()
	if blob.data != nil && blob.length > 0 && uint64(blob.length) <= uint64(^uint(0)>>1) {
		result.smbios = C.GoBytes(blob.data, C.int(blob.length))
		C.free(blob.data)
	}
	return result
}

func darwinRecordsFromC(output *C.char) []darwinRecord {
	if output == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(output))
	text := C.GoString(output)
	if text == "" {
		return nil
	}
	records := make([]darwinRecord, 0)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) == 0 || fields[0] == "" {
			continue
		}
		record := darwinRecord{"kind": fields[0]}
		for index := 1; index+1 < len(fields); index += 2 {
			if fields[index] != "" && fields[index+1] != "" {
				record[fields[index]] = fields[index+1]
			}
		}
		records = append(records, record)
	}
	return records
}

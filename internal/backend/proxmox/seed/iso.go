package seed

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// The image layout, in 2048-byte sectors:
//
//	0-15   zeros (system area)
//	16     Primary Volume Descriptor, volume id "cidata"
//	17     Supplementary Volume Descriptor: Joliet, UCS-2 level 3
//	18     Volume Descriptor Set Terminator
//	19-22  path tables: primary L and M, Joliet L and M
//	23     primary root directory: META_DATA.;1, NETWORK_CONFIG.;1, USER_DATA.;1
//	24     Joliet root directory: meta-data;1, network-config;1, user-data;1
//	25...  one extent per non-empty file, shared by both trees
//
// There is no Rock Ridge, boot record or subdirectory. Linux isofs, FreeBSD
// cd9660, Windows and libarchive read the Joliet names when there is no Rock
// Ridge. The primary names use ISO 9660 level 2 (up to 30 characters). An
// empty file has extent 0 and length 0.
const (
	sectorSize       = 2048
	primarySector    = 16
	jolietSector     = 17
	terminatorSector = 18
	pathTableSector  = 19
	primaryRoot      = 23
	jolietRoot       = 24
	firstExtent      = 25
	pathTableSize    = 10
	volumeID         = "cidata"
)

// Every date in the image is 2000-01-01 00:00:00 UTC, so the bytes depend on
// the files alone: recorded in a directory record (years since 1900, month,
// day, hour, minute, second, zone), volumeDate in a descriptor, and unsetDate
// for the expiration and effective dates.
const (
	recorded   = "\x64\x01\x01\x00\x00\x00\x00"
	volumeDate = "2000010100000000\x00"
	unsetDate  = "0000000000000000\x00"
)

// image writes the files, at most three, sorted by name, into an ISO 9660
// image with a Joliet tree.
func image(files []file) []byte {
	extents := make([]uint32, len(files))
	next := uint32(firstExtent)
	for i, f := range files {
		if len(f.data) > 0 {
			extents[i] = next
			next += uint32((len(f.data) + sectorSize - 1) / sectorSize)
		}
	}
	img := make([]byte, int(next)*sectorSize)
	sector := func(n uint32) []byte { return img[n*sectorSize : (n+1)*sectorSize] }

	primary, joliet := make([][]byte, len(files)), make([][]byte, len(files))
	for i, f := range files {
		primary[i] = []byte(strings.ToUpper(strings.ReplaceAll(f.name, "-", "_")) + ".;1")
		joliet[i] = ucs2(f.name + ";1")
		copy(img[extents[i]*sectorSize:], f.data)
	}
	descriptor(sector(primarySector), 1, next, primaryRoot, pathTableSector, pathTableSector+1, false)
	descriptor(sector(jolietSector), 2, next, jolietRoot, pathTableSector+2, pathTableSector+3, true)
	copy(sector(terminatorSector), "\xffCD001\x01")
	for i, root := range []uint32{primaryRoot, primaryRoot, jolietRoot, jolietRoot} {
		table := sector(pathTableSector + uint32(i))
		table[0] = 1 // the root's identifier is one byte, 0x00
		order := binary.ByteOrder(binary.LittleEndian)
		if i%2 == 1 {
			order = binary.BigEndian
		}
		order.PutUint32(table[2:], root)
		order.PutUint16(table[6:], 1)
	}
	for _, tree := range []struct {
		root  uint32
		names [][]byte
	}{{primaryRoot, primary}, {jolietRoot, joliet}} {
		dir := sector(tree.root)
		dir = dir[copy(dir, record([]byte{0}, tree.root, sectorSize, 2)):]
		dir = dir[copy(dir, record([]byte{1}, tree.root, sectorSize, 2)):]
		for i, name := range tree.names {
			dir = dir[copy(dir, record(name, extents[i], uint32(len(files[i].data)), 0)):]
		}
	}
	return img
}

// descriptor writes a primary (kind 1) or Joliet supplementary (kind 2)
// volume descriptor.
func descriptor(d []byte, kind byte, sectors, root, lTable, mTable uint32, joliet bool) {
	d[0] = kind
	copy(d[1:], "CD001\x01")
	text := func(field []byte, s string) {
		if !joliet {
			copy(field, s+strings.Repeat(" ", len(field)-len(s)))
			return
		}
		u := ucs2(s + strings.Repeat(" ", len(field)/2-len(s)))
		copy(field, u) // an odd last byte stays 0
	}
	text(d[8:40], "")
	text(d[40:72], volumeID)
	both32(d[80:], sectors)
	if joliet {
		copy(d[88:], "%/E")
	}
	both16(d[120:], 1)
	both16(d[124:], 1)
	both16(d[128:], sectorSize)
	both32(d[132:], pathTableSize)
	binary.LittleEndian.PutUint32(d[140:], lTable)
	binary.BigEndian.PutUint32(d[148:], mTable)
	copy(d[156:190], record([]byte{0}, root, sectorSize, 2))
	for _, f := range [][2]int{{190, 318}, {318, 446}, {446, 574}, {574, 702}, {702, 739}, {739, 776}, {776, 813}} {
		text(d[f[0]:f[1]], "")
	}
	copy(d[813:], volumeDate)
	copy(d[830:], volumeDate)
	copy(d[847:], unsetDate)
	copy(d[864:], unsetDate)
	d[881] = 1
}

// record is a directory record; flags 2 marks a directory.
func record(id []byte, extent, size uint32, flags byte) []byte {
	n := 33 + len(id)
	n += n % 2
	r := make([]byte, n)
	r[0] = byte(n)
	both32(r[2:], extent)
	both32(r[10:], size)
	copy(r[18:25], recorded)
	r[25] = flags
	both16(r[28:], 1)
	r[32] = byte(len(id))
	copy(r[33:], id)
	return r
}

func both16(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b, v)
	binary.BigEndian.PutUint16(b[2:], v)
}

func both32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b, v)
	binary.BigEndian.PutUint32(b[4:], v)
}

// ucs2 encodes s, which is ASCII here, as UCS-2 big endian.
func ucs2(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.BigEndian.PutUint16(b[2*i:], u)
	}
	return b
}

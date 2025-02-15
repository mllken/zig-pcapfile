// Pcap (Legacy) file reader and writer
//
// https://wiki.wireshark.org/Development/LibpcapFileFormat
// TODO: pcapng.zig

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const time = std.time;

pub const Magic = enum(u32) {
    MicroSeconds = 0xa1b2c3d4,
    NanoSeconds = 0xa1b23c4d,
    MicroSecondsBE = 0xd4c3d2d1,
    NanoSecondsBE = 0x4d3cb1a1,
    _,
};

pub const major_version = 2;
pub const minor_version = 4;

/// The default maximum snapshot length (matches tcpdump's default)
pub const default_max_snap_len = 262144;

/// The global header length
const file_header_len = 24;
/// The packet record length
const record_header_len = 16;

/// The global file header
pub const FileHeader = extern struct {
    magic: u32 = @intFromEnum(Magic.MicroSeconds),
    major: u16 = major_version,
    minor: u16 = minor_version,
    reserved1: u32 = 0,
    reserved2: u32 = 0,
    snap_len: u32 = default_max_snap_len,
    network: u32 = @intFromEnum(LinkType.ETHERNET),
};

/// The packet record header for each packet.
pub const RecordHeader = extern struct {
    ts_sec: u32 = 0,
    ts_usec: u32 = 0,
    incl_len: u32 = 0,    
    orig_len: u32 = 0,  
};

comptime {
    std.debug.assert(@sizeOf(FileHeader) == file_header_len);
    std.debug.assert(@sizeOf(RecordHeader) == record_header_len);
}

pub const default_buffer_size = 65536;

pub const IteratorOptions = struct {
    /// size of the reusable buffer to allocate.
    buffer_size: usize = default_buffer_size,
};

/// An iterator of pcap packet records.
pub fn Iterator(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        reader: ReaderType,
        buf: []u8,
        endian: std.builtin.Endian,
        header: FileHeader,

        /// Read a FileHeader from reader and return an packet record iterator.
        pub fn init(allocator: mem.Allocator, options: IteratorOptions, reader: anytype) !Self {
            const hdr_bytes = try reader.readBytesNoEof(file_header_len);
            const magic = mem.readInt(u32, hdr_bytes[0..4], .little);
            const endian: std.builtin.Endian = switch (@as(Magic, @enumFromInt(magic))) {
                .MicroSeconds, .NanoSeconds => .little,
                .MicroSecondsBE, .NanoSecondsBE => .big,
                _ => return error.BadMagic,
            };
            const hdr = FileHeader{
                .magic = magic,
                .major = mem.readInt(u16, hdr_bytes[4..6], endian),
                .minor = mem.readInt(u16, hdr_bytes[6..8], endian),
                .reserved1 = 0,
                .reserved2 = 0,
                .snap_len = mem.readInt(u32, hdr_bytes[16..20], endian),
                .network = mem.readInt(u32, hdr_bytes[20..24], endian),
            };
            if (hdr.major != major_version or hdr.minor != minor_version) {
                return error.UnsupportedVersion;
            }
            const buf = try allocator.alloc(u8, options.buffer_size);
            errdefer allocator.free(buf);

            return Self {
                .reader = reader,
                .buf = buf,
                .endian = endian,
                .header = hdr,
            };
        }

        /// Get the next packet record.  *IMPORTANT* The returned data is only valid until the next
        /// call to next().  TODO: have this return a 'anonymous tuple', once Zig has those.
        pub fn next(self: *Self) !?struct { hdr: RecordHeader, data: []const u8 } {
            const tmp = self.reader.readBytesNoEof(record_header_len) catch |err| switch (err) {
                error.EndOfStream => return null,
                else => |e| return e,
            };
            const incl_len = mem.readInt(u32, tmp[8..12], self.endian);
            if (incl_len > self.buf.len) return error.RecordTooBig;

            try self.reader.readNoEof(self.buf[0..incl_len]);

            const hdr = RecordHeader{
                .ts_sec = mem.readInt(u32, tmp[0..4], self.endian),
                .ts_usec = mem.readInt(u32, tmp[4..8], self.endian),
                .incl_len = incl_len,
                .orig_len = mem.readInt(u32, tmp[12..16], self.endian),
            };
            return .{ .hdr = hdr, .data = self.buf[0..incl_len] };
        }

        pub fn deinit(self: *Self, allocator: mem.Allocator) void {
            allocator.free(self.buf);
        }
    };
}

pub fn iterator(allocator: mem.Allocator, options: IteratorOptions, reader: anytype) !Iterator(@TypeOf(reader)) {
    return Iterator(@TypeOf(reader)).init(allocator, options, reader);
}

pub const Precision = enum(u1) {
    Micro,
    Nano,
};

pub const WriterOptions = struct {
    snap_len: u32 = default_max_snap_len,
    network: LinkType = .ETHERNET,
    precision: Precision = .Micro,
    endian: std.builtin.Endian = .little,
};

pub fn PcapWriter(comptime WriterType: type) type {
    return struct {
        const Self = @This();

        writer: WriterType,
        options: WriterOptions,

        pub fn init(options: WriterOptions, writer: anytype) Self {
            return Self {
                .writer = writer,
                .options = options,
            };
        }

        /// Write out the file header.  Usually called before writing out any records, unless appending to an existing pcap.
        pub fn writeFileHeader(self: *Self) !void {
            const magic: Magic = switch (self.options.precision) {
                .Micro => Magic.MicroSeconds,
                .Nano => Magic.NanoSeconds,
            };
            const hdr = FileHeader{
                .magic = @intFromEnum(magic),
                .snap_len = self.options.snap_len,
                .network = @intFromEnum(self.options.network),
            };
            const e = self.options.endian;
            try self.writer.writeInt(u32, hdr.magic, e);
            try self.writer.writeInt(u16, hdr.major, e);
            try self.writer.writeInt(u16, hdr.minor, e);
            try self.writer.writeInt(u32, 0, e);
            try self.writer.writeInt(u32, 0, e);
            try self.writer.writeInt(u32, hdr.snap_len, e);
            try self.writer.writeInt(u32, hdr.network, e);
        }

        /// Write a single record to the writer.  When any record header values are zero, sane values are chosen.
        pub fn writeRecord(self: *Self, hdr: RecordHeader, data: []const u8) !void {
            // Length sanity checks
            // We don't check against FileHeader's snaplen, as reader tools usually ignore this.
            const incl_len: u32 = if (hdr.incl_len == 0) @truncate(data.len) else hdr.incl_len;
            if (incl_len != data.len)
                return error.PacketLenMismatch;

            const orig_len: u32 = if (hdr.orig_len == 0) @truncate(data.len) else hdr.orig_len;
            if (incl_len > orig_len)
                return error.PacketInvalidOrigLen;

            const ts = if (hdr.ts_sec == 0) blk: {
                const ts_nano = time.nanoTimestamp();
                const secs: u32 = @truncate(@as(u128, @bitCast(@divFloor(ts_nano, time.ns_per_s))));
                const usecs: u32 = switch (self.options.precision) {
                    .Micro => u: {
                        const ts_micro = @divFloor(ts_nano, time.ns_per_us);
                        break :u @truncate(@rem(@as(u128, @bitCast(ts_micro)), time.us_per_s));
                    },
                    .Nano => @truncate(@rem(@as(u128, @bitCast(ts_nano)), time.ns_per_s)),
                };
                break :blk .{ secs, usecs };
            } else
                .{ hdr.ts_sec, hdr.ts_usec };

            var buf: [16]u8 = undefined;
            const e = self.options.endian;
            mem.writeInt(u32, buf[0..4], ts[0], e);
            mem.writeInt(u32, buf[4..8], ts[1], e);
            mem.writeInt(u32, buf[8..12], incl_len, e);
            mem.writeInt(u32, buf[12..16], orig_len, e);

            try self.writer.writeAll(&buf);
            try self.writer.writeAll(data);
        }
    };
}

pub fn initWriter(options: WriterOptions, writer: anytype) PcapWriter(@TypeOf(writer)) {
    return PcapWriter(@TypeOf(writer)).init(options, writer);
}

pub const LinkType = enum(u32) {
    NULL = 0,
    ETHERNET = 1,  // Default, most common
    AX25 = 3,
    IEEE802_5 = 6,
    ARCNET_BSD = 7,
    SLIP = 8,
    PPP = 9,
    FDDI = 10,
    PPP_HDLC = 50,
    PPP_ETHER,
    ATM_RFC1483 = 100,
    RAW = 101,
    C_HDLC = 104,
    IEEE802_11 = 105,
    FRELAY = 107,
    LOOP = 108,
    LINUX_SLL = 113,
    LTALK = 114,
    PFLOG = 117,
    IEEE802_11_PRISM = 119,
    IP_OVER_FC = 122,
    SUNATM = 123,
    IEEE802_11_RADIOTAP = 127,
    ARCNET_LINUX = 129,
    APPLE_IP_OVER_IEEE1394 = 138,
    MTP2_WITH_PHDR = 139,
    MTP2 = 140,
    MTP3 = 141,
    SCCP = 142,
    DOCSIS = 143,
    LINUX_IRDA = 144,
    USER0 = 147,
    USER1,
    USER2,
    USER3,
    USER4,
    USER5,
    USER6,
    USER7,
    USER8,
    USER9,
    USER10,
    USER11,
    USER12,
    USER13,
    USER14,
    USER15,
    IEEE802_11_AVS = 163,
    BACNET_MS_TCP = 165,
    PPP_PPPD = 166,
    GPRS_LLC = 169,
    GPF_T = 170,
    GPF_F,
    LINUX_LAPD = 177,
    MFR = 182,
    BLUETOOTH_HCI_H4 = 187,
    USB_LINUX = 189,
    PPI = 192,
    IEEE80211_15_4_WITHFCS = 195,
    SITA = 196,
    ERF = 197,
    BLUETOOTH_HCI_H4_WITH_PHDR = 201,
    AX25_KISS = 202,
    LAPD = 203,
    PPP_WITH_DIR = 204,
    C_HDLC_WITH_DIR = 205,
    FRELAY_WITH_DIR = 206,
    LAPB_WITH_DIR = 207,
    IPMB_LINUX = 209,
    FLEXRAY = 210,
    LIN = 212,
    IEEE802_15_4_NONASK_PHY = 215,
    USB_LINUX_MMAPPED = 220,
    FC_2 = 224,
    FC_2_WITH_FRAME_DELIMS,
    IPNET = 226,
    CAN_SOCKETCAN = 227,
    IPV4 = 228,
    IPV6 = 229,
    IEEE802_15_4_NOFCS = 230,
    DBUS = 231,
    DVB_CI = 235,
    MUX27010 = 236,
    STANAG_5066_D_PDU = 237,
    NFLOG = 239,
    NETANALYZER = 240,
    NETANALYZER_TRANSPARENT,
    IPOIB = 242,
    MPEG_2_TS = 243,
    NG40 = 244,
    NFC_LLCP = 245,
    INFINIBAND = 247,
    SCTP = 248,
    USBPCAP = 249,
    RTAC_SERIAL = 250,
    BLUETOOTH_LE_LL = 251,
    NETLINK = 253,
    BLUETOOTH_LINUX_MONITOR = 254,
    BLUETOOTH_BREDR_BB,
    BLUETOOTH_LE_LL_WITH_PHDR,
    PROFIBUS_DL = 257,
    PKTAP = 258,
    EPON = 259,
    IPMI_HPM_2 = 260,
    ZWAVE_R1_R2 = 261,
    ZWAVE_R3 = 262,
    WATTSTOPPER_DLM = 263,
    ISO_14443 = 264,
    RDS = 265,
    USB_DARWIN = 266,
    SDLC = 268,
    LORATAP = 270,
    VSOCK = 271,
    NORDIC_BLE = 272,
    DOCSIS31_XRA31 = 273,
    ETHERNET_MPACKET = 274,
    DISPLAYPORT_AUX = 275,
    LINUX_SLL2 = 276,
    OPENVIZSLA = 278,
    EBHSCR = 279,
    VPP_DISPATCH = 280,
    DSA_TAG_BRCM = 281,
    DSA_TAG_BRCM_PREPEND,
    IEEE802_15_4_TAP = 283,
    DSA_TAG_DSA = 284,
    DSA_TAG_EDSA,
    ELEE = 286,
    Z_WAVE_SERIAL = 287,
    USB_2_0 = 288,
    ATSC_ALP = 289,
    ETW = 290,
    ZBOSS_NCP = 292,
    USB_2_0_LOW_SPEED = 293,
    USB_2_0_FULL_SPEED,
    USB_2_0_HIGH_SPEED,
    AUERSWALD_LOG = 296,
    _,
};

test "pcap" {
    const pcap = @This();
    const allocator = std.testing.allocator;

    // this test PCAP is taken from www.tcpdump.org.  It has a snaplen of 65535.
    const pcap_bytes: []const u8 = @embedFile("testdata/icmpv6.pcap");
    var in_bytes = std.io.fixedBufferStream(pcap_bytes);

    var out_buf = std.ArrayList(u8).init(allocator);
    defer out_buf.deinit();

    {
        var it = try pcap.iterator(allocator, .{}, in_bytes.reader());
        defer it.deinit(allocator);

        var w = pcap.initWriter(.{ .snap_len = 65535 }, out_buf.writer());
        try w.writeFileHeader();

        while (try it.next()) |rec| {
            try w.writeRecord(rec.hdr, rec.data);
        }
    }
    try std.testing.expectEqualSlices(u8, pcap_bytes, out_buf.items);
}

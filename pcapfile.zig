// Legacy Pcap file format
pub const pcap = @import("pcap.zig");
// Pcap NG
pub const pcapng = @import("pcapng.zig");

test {
    @import("std").testing.refAllDecls(@This());
}

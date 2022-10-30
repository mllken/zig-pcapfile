const std = @import("std");

pub const pkg = std.build.Pkg{
    .name = "zig-pcapfile",
    .source = .{ .path = "pcapfile.zig" },
};

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("zig-pcapfile", "pcapfile.zig");
    lib.setBuildMode(mode);
    lib.install();

    const main_tests = b.addTest("pcapfile.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}

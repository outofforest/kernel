const std = @import("std");
const Target = @import("std").Target;
const CrossTarget = @import("std").zig.CrossTarget;
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "bootx64",
        .root_source_file = b.path("src/main.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = Target.Cpu.Arch.x86_64,
            .os_tag = Target.Os.Tag.uefi,
            .abi = Target.Abi.msvc,
        }),
    });
    b.installArtifact(exe);
    // exe.setBuildMode(b.standardReleaseOptions());
    // exe.setOutputDir("efi/boot");
    // b.default_step.dependOn(&exe.step);
}

// const std = @import("std");

// pub fn build(b: *std.Build) void {
//     const exe = b.addExecutable(.{
//         .name = "hello",
//         .root_source_file = b.path("src/main.zig"),
//         .target = b.standardTargetOptions(.{}),
//         .optimize = b.standardOptimizeOption(.{}),
//     });

//     b.installArtifact(exe);
// }

"""Hermetic LLVM example helpers."""

load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@with_cfg.bzl", "with_cfg")

glibc_cc_binary, _glibc_cc_binary = (
    with_cfg(cc_binary)
        .set("platforms", [Label("@llvm//platforms:linux_x86_64_gnu.2.28")])
        .build()
)

musl_cc_binary, _musl_cc_binary = (
    with_cfg(cc_binary)
        .set("platforms", [Label("@llvm//platforms:linux_x86_64_musl")])
        .build()
)

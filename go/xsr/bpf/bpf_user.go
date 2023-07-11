package bpf

// #include <linux/bpf.h>
// int border_router(struct xdp_md* ctx);
// #cgo LDFLAGS: xsr_native.a libaes.a
import "C"

func NativeXSR() {
	ctx := C.struct_xdp_md{}
	C.border_router(&ctx)
}

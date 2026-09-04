package der

import "unsafe"

func uintptrOf(p *byte) uintptr { return uintptr(unsafe.Pointer(p)) }

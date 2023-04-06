
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-cxl.h"


void qmp_cxl_process_dynamic_capacity_event(const char *path, CxlEventLog log,
		uint8_t flags, uint8_t type, uint16_t hid, uint8_t rid,
		const char *extent, Error **errp)
{
    error_setg(errp, "CXL DCD support is not compiled in");
}

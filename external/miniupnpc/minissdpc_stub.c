// Windows stub: no MiniSSDPd, so return NULL.
#include "minissdpc.h"
#include "miniupnpc.h"

struct UPNPDev* getDevicesFromMiniSSDPD(const char* devtype, const char* socketpath)
{
    (void)devtype;
    (void)socketpath;
    return 0;
}
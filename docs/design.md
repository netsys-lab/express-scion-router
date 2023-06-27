eXpress SCION Router Design
===========================


AS-internal Routing
-------------------
Every border router has a dummy interface with index 0. The dummy interface must
never go down. An IP address must be assigned to the dummy interface.

### Option 1: Kernel Routing
When a packet must be send to a sibling border router, the sending BR looks up
its siblings' IP address in the kernel's FIB. The packet is send using the
source and destination addresses returned by the kernel on the source port
indicated by the kernel.

### Option 2: Internal Routing
When a packet must be send to a sibling router, the sending BR consults it's
own routing table to find a suitable next hop entry.

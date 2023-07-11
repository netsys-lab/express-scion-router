#include <linux/bpf.h>

int border_router(struct xdp_md* ctx);


int main()
{
    struct xdp_md ctx = {0};
    return border_router(&ctx);
}

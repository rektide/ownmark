#ifndef _XT_OWNMARK_H
#define _XT_OWNMARK_H

#include <linux/types.h>

struct xt_ownmark_tginfo1 {
        __u32 id_min, id_max;
        __u32 mask, shift;
};

#endif /*_XT_OWNMARK_H*/

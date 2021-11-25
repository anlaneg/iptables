#ifndef _XT_U32_H
#define _XT_U32_H 1

#include <linux/types.h>

enum xt_u32_ops {
	XT_U32_AND,//与操作
	XT_U32_LEFTSH,//左移操作
	XT_U32_RIGHTSH,//右移操作
	XT_U32_AT,
};

struct xt_u32_location_element {
	__u32 number;
	__u8 nextop;//运算符
};

struct xt_u32_value_element {
	__u32 min;
	__u32 max;
};

/*
 * Any way to allow for an arbitrary number of elements?
 * For now, I settle with a limit of 10 each.
 */
#define XT_U32_MAXSIZE 10

struct xt_u32_test {
	struct xt_u32_location_element location[XT_U32_MAXSIZE+1];
	struct xt_u32_value_element value[XT_U32_MAXSIZE+1];
	__u8 nnums;//location数组长度
	__u8 nvalues;//value数组长度
};

struct xt_u32 {
	struct xt_u32_test tests[XT_U32_MAXSIZE+1];
	__u8 ntests;//tests数组大小
	__u8 invert;//是否反向选择
};

#endif /* _XT_U32_H */

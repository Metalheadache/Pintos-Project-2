#ifndef THREAD_FIXED_POINT_H
#define THREAD_FIXED_POINT_H

/* Definitions of fixed-point. */
typedef int fixed_point;

/* We use 16 LSB number as the fractional part. */
#define FP_SHIFT_AMOUNT 16

/* Algorithm for converting a value to a fixed-point value. */
#define FP_CONVT(A) ((fixed_point)(A << FP_SHIFT_AMOUNT))

/* Algorithm for adding two fixed-point values together. */
#define FP_ADD(A,B) (A + B)

/* Algorithm for adding a fixed-point value A and an int value B together. */
#define FP_ADD_MIX(A,B) (A + (B << FP_SHIFT_AMOUNT))

/* Algorithm for substracting a fixed-point value B from a fixed-point value A. */
#define FP_SUB(A,B) (A - B)

/* Algorithm for substracting an int value B from a fixed-point value A. */
#define FP_SUB_MIX(A,B) (A - (B << FP_SHIFT_AMOUNT))

/* Algorithm for multiplying two fixed-point value together. */
#define FP_MULT(A,B) ((fixed_point)(((int64_t) A) * B >> FP_SHIFT_AMOUNT))

/* Algorithm for multiplying a fixed-point value A by an int value B. */
#define FP_MULT_MIX(A,B) (A * B)

/* Algorithm for dividing a fixed-point value A by a fixed-point value B. */
#define FP_DIV(A,B) ((fixed_point)((((int64_t) A) << FP_SHIFT_AMOUNT) / B))

/* Algorithm for dividing a fixed-point value A by an int value B. */
#define FP_DIV_MIX(A,B) (A / B)

/* Algorithm for getting the integer part of a fixed-point value. */
#define FP_INT_PART(A) (A >> FP_SHIFT_AMOUNT)

/* Algorithm for getting the rounded integer of a fixed-point value. */
#define FP_ROUND(A) (A >= 0 ? ((A + (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT) : ((A - (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT))

#endif
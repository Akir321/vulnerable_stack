#ifndef STACK_H
#define STACK_H

typedef int elem_t;
#define elemFormat "%d"

#ifdef  CANARY_PROTECTION
#undef  CANARY_PROTECTION
#endif

#ifdef    HASH_PROTECTION
#undef    HASH_PROTECTION
#endif

#define CANARY_PROTECTION(...) __VA_ARGS__
#define   HASH_PROTECTION(...) __VA_ARGS__

const size_t DEFAULT_CAPACITY = 8;
const size_t LAST_PRINTED     = 16;
const size_t ELEM_PRINT_ADD   = 4;
const size_t REALLOC_RATE     = 2;

const unsigned int HASH_BASE  = 128;
const unsigned int HASH_MOD   = 11113;

const unsigned long long STK_CANARY = 0xDEADBEEF;
const unsigned long long BUF_CANARY = 0xFACEFEED;

struct stack
{
    CANARY_PROTECTION( long long stackCanary1; )
    elem_t *data;

    size_t capacity;
    size_t size;

    HASH_PROTECTION  ( unsigned hash; )
    CANARY_PROTECTION( long long stackCanary2; )
};

struct stackErrorField
{
    unsigned stack_null     : 1;
    unsigned data_null      : 1;
    unsigned small_capacity : 1;
    unsigned anti_overflow  : 1;
    unsigned realloc_failed : 1;
    unsigned changed_canary : 1;
    unsigned changed_hash   : 1;
};

stackErrorField stackError(stack *stk);

stackErrorField stackCtor(stack *stk, size_t capacity);

stackErrorField stackDtor(stack *stk);

stackErrorField stackDump(stack *stk, const char *file, int line, const char *function);

void printStackErrors(stackErrorField error);

#define STACK_DUMP(stk) stackDump((stk), __FILE__, __LINE__, __func__);

stackErrorField stackPush(stack *stk, elem_t value);

stackErrorField stackPop(stack *stk, elem_t *returnValue);

stackErrorField stackRealloc(stack *stk);

void *myCalloc(size_t elementNum, size_t elementSize);

unsigned int stackHashCalc(stack *stk);

stackErrorField stackHashCheck(stack *stk);

unsigned errorFieldToU(stackErrorField error);

#endif //STACK_H

#include <stdio.h>
#include <unistd.h>

#define SYS_CALL_ERROR (-1)
#define SBRK_ERROR (void*)SYS_CALL_ERROR
#define EXIT_SUCCESS (0)
#define EXIT_FAILURE (-1)


typedef struct HEADER_TAG {
    struct HEADER_TAG* ptr_next;
    struct HEADER_TAG* ptr_prev;
    size_t bloc_size;
    long magic_number;
} HEADER;

#define HEADER_SIZE sizeof(HEADER)

void* malloc_3is(size_t size);
// void free_3is(const void* ptr);

HEADER* get_head_of_size(size_t size);

HEADER* head = NULL;


HEADER* get_head_of_size(size_t size) {
    HEADER* cur_head = head;
    while (cur_head != NULL) {
        if (cur_head->bloc_size <= size) {
            cur_head->ptr_next->ptr_prev = cur_head->ptr_prev;
            cur_head->ptr_prev->ptr_next = cur_head->ptr_next;
            return cur_head;
        }
        cur_head = cur_head->ptr_next;
    }
    return NULL;
}

void* malloc_3is(const size_t size) {
    if (size == 0) {
        return NULL;
    }

    HEADER* available_block = get_head_of_size(size);
    if (available_block != NULL) {
        return available_block;
    }

    void* start_ptr = sbrk(size);
    void* end_ptr = sbrk(0);
    if (end_ptr == SBRK_ERROR) {
        perror("malloc_3is: sbrk failed");
        return NULL;
    }
    return start_ptr;
}


int main(void) {
    printf("TP2: allocateur mémoire\n");

    void* test = malloc_3is(4);
    printf("test 1: %p\n", test);

    test = malloc_3is(4);
    printf("test 2: %p\n", test);

    return EXIT_SUCCESS;
}
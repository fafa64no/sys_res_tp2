#include <stdio.h>
#include<unistd.h>

#define SYS_CALL_ERROR (-1)
#define SBRK_ERROR (void*)SYS_CALL_ERROR

#define MINIMUM_BLOCK_SIZE 0xff


typedef struct HEADER_TAG {
    struct HEADER_TAG* ptr_next;
    size_t bloc_size;
    long magic_number;
} HEADER;

#define HEADER_SIZE sizeof(HEADER)
#define BLOCK_SIZE (MINIMUM_BLOCK_SIZE + HEADER_SIZE)

void* malloc_3is(size_t size);
// void free_3is(const void* ptr);

size_t get_size_to_increase(size_t size_requested);

HEADER* head = NULL;


// size_t get_size_to_increase(size_t size_requested) {
//     size_t minimum_to_allocate = size_requested + HEADER_SIZE;
//     size_t already_allocated = 0;
//     if (head != NULL) {
//
//     }
//
//     const size_t nb_blocks = (minimum_to_allocate - already_allocated) / MINIMUM_BLOCK_SIZE;
//     return (nb_blocks + 1) * MINIMUM_BLOCK_SIZE;
// }

void* malloc_3is(const size_t size) {
    if (size == 0) {
        return NULL;
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
    return 0;
}
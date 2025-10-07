#include <stdio.h>
#include <unistd.h>

#define SYS_CALL_ERROR (-1)
#define MAP_FAILED (void*)SYS_CALL_ERROR
#define EXIT_SUCCESS (0)
#define EXIT_FAILURE (-1)

#define MAGIC_NUMBER 0x0123456789ABCDEFL


typedef struct HEADER_TAG {
    struct HEADER_TAG* ptr_next;
    struct HEADER_TAG* ptr_prev;
    size_t bloc_size;
    long magic_number;
} HEADER;

#define HEADER_SIZE sizeof(HEADER)
#define MAGIC_NUMBER_SIZE sizeof(long long)


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

    void* start_ptr = sbrk((long) (size + HEADER_SIZE + MAGIC_NUMBER_SIZE));
    void* end_ptr = sbrk(0);
    if (end_ptr == MAP_FAILED) {
        perror("malloc_3is: sbrk failed");
        return NULL;
    }

    HEADER* header_ptr = (HEADER*)start_ptr;
    header_ptr->ptr_next = NULL;
    header_ptr->ptr_prev = NULL;
    header_ptr->bloc_size = size;
    header_ptr->magic_number = MAGIC_NUMBER;
    header_ptr++;

    start_ptr += HEADER_SIZE + size;
    *((long long*) start_ptr) = MAGIC_NUMBER;

    return header_ptr;
}


int main(void) {
    printf("TP2: allocateur mémoire\n");

    void* test = malloc_3is(4);
    printf("test 1: %p\n", test);

    test = malloc_3is(4);
    printf("test 2: %p\n", test);

    return EXIT_SUCCESS;
}
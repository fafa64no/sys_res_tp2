#include <stdio.h>
#include <unistd.h>

#define SYS_CALL_ERROR (-1)
#define MAP_FAILED (void*)SYS_CALL_ERROR
#define EXIT_SUCCESS (0)
#define EXIT_FAILURE (-1)
#define TRUE 1
#define FALSE 0

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
void free_3is(void* ptr);
long long check_magic_number(void* ptr);

HEADER* get_block_of_size(size_t size);
HEADER* extract_block(HEADER* block);

void test_allocation();
void test_magic_number();
void test_free();

HEADER* head = NULL;
int do_print_allocation_type = 0;


void enable_allocation_type_printing() {
    do_print_allocation_type = TRUE;
}

void disable_allocation_type_printing() {
    do_print_allocation_type = FALSE;
}


HEADER* get_block_of_size(size_t size) {
    HEADER* cur_head = head;
    while (cur_head) {
        if (cur_head->bloc_size >= size) {
            return extract_block(cur_head);
        }
        cur_head = cur_head->ptr_prev;
    }
    return NULL;
}

HEADER* extract_block(HEADER* block) {
    if (block == NULL) {
        perror("extract_block: NULL block\n");
        return NULL;
    }

    /// TODO: Split the block if too big
    if (block == head) {
        if (block->ptr_prev) {
            head = block->ptr_prev;
        } else {
            head = NULL;
        }
    }

    if (block->ptr_next) {
        block->ptr_next->ptr_prev = block->ptr_prev;
    }

    if (block->ptr_prev) {
        block->ptr_prev->ptr_next = block->ptr_next;
    }

    block->ptr_next = NULL;
    block->ptr_prev = NULL;

    return block;
}

void* malloc_3is(const size_t size) {
    if (size == 0) {
        return NULL;
    }

    HEADER* available_block = get_block_of_size(size);
    if (available_block) {
        if (do_print_allocation_type) {
            printf("malloc_3is: Reusing allocated memory\n");
        }
        return ++available_block;
    }

    /// TODO: Preallocate memory
    void* start_ptr = sbrk((long) (size + HEADER_SIZE + MAGIC_NUMBER_SIZE));
    void* end_ptr = sbrk(0);
    if (end_ptr == MAP_FAILED) {
        perror("malloc_3is: sbrk failed\n");
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

    if (do_print_allocation_type) {
        printf("malloc_3is: New allocated memory\n");
    }
    return header_ptr;
}

void free_3is(void* ptr) {
    if (ptr == NULL) {
        return;
    }

    if (check_magic_number(ptr)) {
        perror("free_3is: bad magic number\n");
        return;
    }

    HEADER* head_ptr = (HEADER*) ptr;
    head_ptr--;
    if (head == NULL) {
        head = head_ptr;
    } else {
        head->ptr_next = head_ptr;
        head->ptr_prev = head;
        head = head_ptr;
    }

    /// TODO: Combine the block if adjacent
}

long long check_magic_number(void* ptr) {
    if (ptr == NULL) {
        return 0;
    }

    // Expects a pointer after the header block
    HEADER* head_ptr = (HEADER*) ptr;
    head_ptr--;
    long long expected_magic_number = head_ptr->magic_number;

    ptr += head_ptr->bloc_size;
    long long actual_magic_number = *((long long*) ptr);

    return expected_magic_number - actual_magic_number;
}


void test_allocation() {
    printf("\n===================== TEST ALLOC =====================\n");
    disable_allocation_type_printing();

    void* test = malloc_3is(0x004);
    printf("\t- test_allocation: 1st alloc %p\n", test);

    test = malloc_3is(0x0f0);
    printf("\t- test_allocation: 2nd alloc %p\n", test);

    // We accept the memory leak here, so that we don't interfere with the test_free() method
    printf("=================== FIN TEST ALLOC ===================\n");
}

void test_magic_number() {
    printf("\n================= TEST MAGIC NUMBER ==================\n");
    disable_allocation_type_printing();

    char* test = (char*) malloc_3is(2);
    printf("\t- test_magic_number: Before magic number break: magic number check: %lld\n", check_magic_number(test));

    test[3] = 'K';
    printf("\t- test_magic_number: After magic number break: magic number check: %lld\n", check_magic_number(test));

    // We accept the memory leak here, so that we don't interfere with the test_free() method
    printf("=============== FIN TEST MAGIC NUMBER ================\n");
}

void test_free() {
    printf("\n====================== TEST FREE =====================\n");
    enable_allocation_type_printing();

    void* test = malloc_3is(0x0f0);
    printf("\t- test_free: 1st allocation %p\n", test);

    free_3is(test);
    test = malloc_3is(0x0f0);
    printf("\t- test_free: 2nd allocation %p\n", test);

    free_3is(test);
    test = malloc_3is(0xfff);
    printf("\t- test_free: 3rd allocation %p\n", test);

    free_3is(test);
    test = malloc_3is(0x0f0);
    printf("\t- test_free: 4th allocation %p\n", test);

    printf("==================== FIN TEST FREE ===================\n");
}


int main(void) {
    printf("TP2: allocateur mémoire\n");

    test_allocation();
    test_magic_number();
    test_free();

    return EXIT_SUCCESS;
}
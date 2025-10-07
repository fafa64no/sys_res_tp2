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
#define BLOCK_ADDITIONAL_SIZE (HEADER_SIZE + MAGIC_NUMBER_SIZE)


void* malloc_3is(size_t size);
void* malloc_3is_debug(size_t size);
void free_3is(void* ptr);
long long check_magic_number(void* ptr);

HEADER* get_block_of_size(size_t size);
HEADER* allocate_block_of_size(size_t size);
HEADER* get_smallest_block_of_BLOCK_ADDITIONAL_SIZE(size_t size);
HEADER* extract_block(HEADER* block);
void insert_block(HEADER* block);
int is_smaller_block(const HEADER* new_block, const HEADER* old_block, size_t min_size);

void test_allocation();
void test_magic_number();
void test_free();

HEADER* HEAD = NULL;


HEADER* get_block_of_size(const size_t size) {
    HEADER* cur_head = HEAD;
    while (cur_head) {
        if (cur_head->bloc_size == size) {
            return extract_block(cur_head);
        }
        cur_head = cur_head->ptr_prev;
    }

    return get_smallest_block_of_BLOCK_ADDITIONAL_SIZE(size);
}

HEADER* allocate_block_of_size(const size_t size) {
    /// TODO: Preallocate memory
    void* start_ptr = sbrk((long) (size + BLOCK_ADDITIONAL_SIZE));
    const void* end_ptr = sbrk(0);
    if (end_ptr == MAP_FAILED) {
        perror("malloc_3is: sbrk failed\n");
        return NULL;
    }

    HEADER* header_ptr = start_ptr;
    header_ptr->ptr_next = NULL;
    header_ptr->ptr_prev = NULL;
    header_ptr->bloc_size = size;
    header_ptr->magic_number = MAGIC_NUMBER;
    header_ptr++;

    start_ptr += HEADER_SIZE + size;
    *(long long*) start_ptr = MAGIC_NUMBER;

    return header_ptr;
}

HEADER* get_smallest_block_of_BLOCK_ADDITIONAL_SIZE(const size_t size) {
    HEADER* cur_head = HEAD;
    HEADER* best_block = NULL;
    while (cur_head) {
        if (is_smaller_block(cur_head, best_block, size)) {
            best_block = cur_head;
        }
        cur_head = cur_head->ptr_prev;
    }

    if (best_block == NULL) {
        return NULL;
    }

    if (best_block->bloc_size - size > BLOCK_ADDITIONAL_SIZE) {
        /// TODO: Split the block;
    }

    return extract_block(best_block);
}

HEADER* extract_block(HEADER* block) {
    if (block == NULL) {
        perror("extract_block: NULL block\n");
        return NULL;
    }

    if (block == HEAD) {
        if (block->ptr_prev) {
            HEAD = block->ptr_prev;
        } else {
            HEAD = NULL;
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

void insert_block(HEADER* block) {
    HEAD->ptr_next = block;
    HEAD->ptr_prev = HEAD;
    HEAD = block;
}

int is_smaller_block(const HEADER* new_block, const HEADER* old_block, const size_t min_size) {
    if (new_block == NULL) {
        perror("smaller_block: NULL block\n");
        return FALSE;
    }

    if (new_block->bloc_size < min_size) {
        return FALSE;
    }

    if (old_block == NULL) {
        return TRUE;
    }

    if (new_block->bloc_size > old_block->bloc_size) {
        return TRUE;
    }

    return FALSE;
}


void* malloc_3is(const size_t size) {
    if (size == 0) {
        return NULL;
    }

    HEADER* available_block = get_block_of_size(size);
    if (available_block) {
        return ++available_block;
    }

    return allocate_block_of_size(size);
}

void* malloc_3is_debug(const size_t size) {
    if (size == 0) {
        return NULL;
    }

    HEADER* available_block = get_block_of_size(size);
    if (available_block) {
        printf("malloc_3is: Reusing allocated memory\n");
        return ++available_block;
    }

    printf("malloc_3is: New allocated memory\n");
    return allocate_block_of_size(size);
}

void free_3is(void* ptr) {
    if (ptr == NULL) {
        return;
    }

    if (check_magic_number(ptr)) {
        perror("free_3is: bad magic number\n");
        return;
    }

    HEADER* head_ptr = ptr;
    head_ptr--;
    if (HEAD == NULL) {
        HEAD = head_ptr;
    } else {
        insert_block(head_ptr);
    }

    /// TODO: Combine the block if adjacent
}

long long check_magic_number(void* ptr) {
    if (ptr == NULL) {
        return 0;
    }

    // Expects a pointer after the header block
    const HEADER* head_ptr = ptr;
    head_ptr--;
    const long long expected_magic_number = head_ptr->magic_number;

    ptr += head_ptr->bloc_size;
    const long long actual_magic_number = *(long long*) ptr;

    return expected_magic_number - actual_magic_number;
}


void test_allocation() {
    printf("\n===================== TEST ALLOC =====================\n");

    void* test = malloc_3is(0x004);
    printf("\t- test_allocation: 1st alloc %p\n", test);

    test = malloc_3is(0x0f0);
    printf("\t- test_allocation: 2nd alloc %p\n", test);

    // We accept the memory leak here, so that we don't interfere with the test_free() method
    printf("=================== FIN TEST ALLOC ===================\n");
}

void test_magic_number() {
    printf("\n================= TEST MAGIC NUMBER ==================\n");

    char* test = malloc_3is(2);
    printf("\t- test_magic_number: Before magic number break: magic number check: %lld\n", check_magic_number(test));

    test[3] = 'K';
    printf("\t- test_magic_number: After magic number break: magic number check: %lld\n", check_magic_number(test));

    // We accept the memory leak here, so that we don't interfere with the test_free() method
    printf("=============== FIN TEST MAGIC NUMBER ================\n");
}

void test_free() {
    printf("\n====================== TEST FREE =====================\n");

    void* test = malloc_3is_debug(0x0f0);
    printf("\t- test_free: 1st allocation %p\n", test);

    free_3is(test);
    test = malloc_3is_debug(0x0f0);
    printf("\t- test_free: 2nd allocation %p\n", test);

    free_3is(test);
    test = malloc_3is_debug(0xfff);
    printf("\t- test_free: 3rd allocation %p\n", test);

    free_3is(test);
    test = malloc_3is_debug(0x0f0);
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
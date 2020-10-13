#include "api/api_types.h"

struct arg_sm_enclave_create { enclave_id_t enclave_id; uintptr_t ev_base; uintptr_t ev_mask; uint64_t num_mailboxes;bool debug ;};
struct arg_sm_enclave_delete { enclave_id_t enclave_id;};
struct arg_sm_enclave_load_page_table { enclave_id_t enclave_id; phys_ptr_t phys_addr; uintptr_t virtual_addr; uint64_t level; uintptr_t acl;};
struct arg_sm_enclave_load_page { enclave_id_t enclave_id; uintptr_t phys_addr; uintptr_t virtual_addr; uintptr_t os_addr; uintptr_t acl;};
struct arg_sm_enclave_metadata_pages { uint64_t num_mailboxes;};
struct arg_sm_get_public_field { public_field_t field; phys_ptr_t phys_addr;};
struct arg_sm_mail_accept { mailbox_id_t mailbox_id; enclave_id_t expected_sender;};
struct arg_sm_mail_receive { mailbox_id_t mailbox_id; phys_ptr_t out_message; phys_ptr_t out_sender_measurement;};
struct arg_sm_mail_send { enclave_id_t enclave_id; mailbox_id_t mailbox_id; phys_ptr_t phys_addr;};
struct arg_sm_region_assign { region_id_t id; enclave_id_t new_owner;};
struct arg_sm_region_block { region_id_t id;};
struct arg_sm_region_flush { void;};
struct arg_sm_region_free { region_id_t id;};
struct arg_sm_region_metadata_create { region_id_t dram_region;};
struct arg_sm_region_metadata_pages {void;};
struct arg_sm_region_metadata_start {void;};
struct arg_sm_region_owner { region_id_t id;};
struct arg_sm_region_state { region_id_t id;};
struct arg_sm_thread_delete { thread_id_t thread_id;};
struct arg_sm_thread_load { enclave_id_t enclave_id; thread_id_t thread_id; uintptr_t entry_pc; uintptr_t entry_stack;};
struct arg_sm_thread_metadata_pages {void;};


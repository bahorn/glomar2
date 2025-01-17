# Block size, using the normal disk size.
BLOCK_SIZE = 4096
AUTHTAG_SIZE = 16
KEYSIZE = 32
NONCE_SIZE = 12

BLOCKS_PER_ROW = 128
BLOCK_ROW_DATA = AUTHTAG_SIZE + NONCE_SIZE
ROW_SIZE = BLOCKS_PER_ROW * BLOCK_SIZE

# nonce and mac
METADATA_OVERHEAD = AUTHTAG_SIZE + NONCE_SIZE

ROW_METADATA_OFFSET = BLOCK_ROW_DATA * (BLOCKS_PER_ROW - 1)
ROW_METADATA_SIZE = BLOCK_SIZE - ROW_METADATA_OFFSET
USABLE_METADATA_SIZE = ROW_METADATA_SIZE - METADATA_OVERHEAD

# Assuming 4 byte ints for indexes
IDX_SIZE = 4
TREE_IDX_COUNT = (ROW_METADATA_SIZE - METADATA_OVERHEAD) // IDX_SIZE

MAX_TRIALS = 64

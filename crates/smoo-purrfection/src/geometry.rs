/// Describes the static layout of the virtual FAT volume.
#[derive(Debug, Clone)]
pub struct Geometry {
    block_size: u32,
    total_blocks: u64,
    reserved_blocks: u32,
    fat_start_block: u64,
    fat_block_count: u64,
    data_start_block: u64,
    blocks_per_cluster: u32,
    total_data_clusters: u64,
}

/// Location of a logical block relative to the well-known on-disk areas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockRegion {
    Reserved(ReservedKind),
    Fat { block_index: u64 },
    Data { block_index: u64 },
}

/// Reserved region blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedKind {
    BootSector,
    FsInfo,
    Other(u32),
}

impl Geometry {
    pub const BLOCK_SIZE: u32 = 4096;
    pub const TOTAL_SIZE_BYTES: u64 = 128 * 1024 * 1024 * 1024;
    pub const TOTAL_BLOCKS: u64 = Self::TOTAL_SIZE_BYTES / Self::BLOCK_SIZE as u64;
    pub const RESERVED_BLOCKS: u32 = 32;
    pub const BLOCKS_PER_CLUSTER: u32 = 16;
    pub const FAT_BLOCK_COUNT: u64 = 2048;

    /// Create a new geometry descriptor using the fixed layout.
    pub const fn new() -> Self {
        let block_size = Self::BLOCK_SIZE;
        let total_blocks = Self::TOTAL_BLOCKS;
        let reserved_blocks = Self::RESERVED_BLOCKS;
        let fat_start_block = reserved_blocks as u64;
        let fat_block_count = Self::FAT_BLOCK_COUNT;
        let data_start_block = fat_start_block + fat_block_count;
        let blocks_per_cluster = Self::BLOCKS_PER_CLUSTER;
        let data_blocks = total_blocks - data_start_block;
        let total_data_clusters = data_blocks / blocks_per_cluster as u64;
        Self {
            block_size,
            total_blocks,
            reserved_blocks,
            fat_start_block,
            fat_block_count,
            data_start_block,
            blocks_per_cluster,
            total_data_clusters,
        }
    }

    /// Logical block size in bytes.
    pub const fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Total amount of logical blocks.
    pub const fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    /// Amount of reserved blocks.
    pub const fn reserved_blocks(&self) -> u32 {
        self.reserved_blocks
    }

    /// Starting block of the FAT area.
    pub const fn fat_start_block(&self) -> u64 {
        self.fat_start_block
    }

    /// Number of logical blocks used by the FAT area.
    pub const fn fat_block_count(&self) -> u64 {
        self.fat_block_count
    }

    /// Starting block of the data region.
    pub const fn data_start_block(&self) -> u64 {
        self.data_start_block
    }

    /// Number of logical blocks per cluster.
    pub const fn blocks_per_cluster(&self) -> u32 {
        self.blocks_per_cluster
    }

    /// Size of a cluster in bytes.
    pub const fn cluster_bytes(&self) -> u64 {
        self.blocks_per_cluster as u64 * self.block_size as u64
    }

    /// Total number of data clusters.
    pub const fn total_data_clusters(&self) -> u64 {
        self.total_data_clusters
    }

    /// Determine the global region that contains the provided logical block index.
    pub const fn region_for_block(&self, lba: u64) -> BlockRegion {
        if lba < self.reserved_blocks as u64 {
            let reserved_index = lba as u32;
            let kind = match reserved_index {
                0 => ReservedKind::BootSector,
                1 => ReservedKind::FsInfo,
                other => ReservedKind::Other(other),
            };
            return BlockRegion::Reserved(kind);
        }
        if lba < self.fat_start_block + self.fat_block_count {
            return BlockRegion::Fat {
                block_index: lba - self.fat_start_block,
            };
        }
        BlockRegion::Data {
            block_index: lba - self.data_start_block,
        }
    }

    /// Convert a data-region block index to the corresponding FAT cluster and block offset.
    pub fn cluster_for_data_block(&self, lba: u64) -> Option<(u32, u32)> {
        if lba < self.data_start_block {
            return None;
        }
        let offset = lba - self.data_start_block;
        let cluster_index = offset / self.blocks_per_cluster as u64;
        if cluster_index >= self.total_data_clusters {
            return None;
        }
        let cluster = 2 + cluster_index as u32;
        let block_in_cluster = (offset % self.blocks_per_cluster as u64) as u32;
        Some((cluster, block_in_cluster))
    }

    /// Convert a cluster number to the absolute LBA of its first block.
    pub fn first_block_of_cluster(&self, cluster: u32) -> Option<u64> {
        if cluster < 2 {
            return None;
        }
        let idx = cluster as u64 - 2;
        if idx >= self.total_data_clusters {
            return None;
        }
        Some(self.data_start_block + idx * self.blocks_per_cluster as u64)
    }
}

use crate::dir::{ClusterKind, FileCatalog};

const FAT_RESERVED0: u32 = 0x0FFFFFF8;
const FAT_RESERVED1: u32 = 0xFFFFFFFF;
const FAT_EOC: u32 = 0x0FFFFFFF;
const FAT_FREE: u32 = 0x00000000;

/// Compute the FAT32 entry for the provided cluster.
pub fn fat_entry(catalog: &FileCatalog, cluster: u32) -> u32 {
    match cluster {
        0 => FAT_RESERVED0,
        1 => FAT_RESERVED1,
        _ => match catalog.cluster_kind(cluster) {
            ClusterKind::Root | ClusterKind::Cats => FAT_EOC,
            ClusterKind::Subdirectory { .. } => FAT_EOC,
            ClusterKind::FileData { cluster_offset, .. } => {
                if cluster_offset + 1 >= catalog.clusters_per_file() {
                    FAT_EOC
                } else {
                    cluster + 1
                }
            }
            ClusterKind::Free => FAT_FREE,
        },
    }
}

use crate::geometry::Geometry;

/// Number of cat subdirectories exposed under `CATS`.
pub const DIRECTORY_COUNT: u32 = 1024;
/// Number of cat images per subdirectory.
pub const FILES_PER_DIRECTORY: u32 = 128;
/// Amount of clusters reserved for each cat image.
pub const CLUSTERS_PER_FILE: u32 = 4;

/// Identifier for a synthetic cat file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    pub dir_index: u32,
    pub file_index: u32,
}

impl FileId {
    pub const fn new(dir_index: u32, file_index: u32) -> Self {
        Self {
            dir_index,
            file_index,
        }
    }

    pub const fn linear_index(&self) -> u64 {
        (self.dir_index as u64) * FILES_PER_DIRECTORY as u64 + self.file_index as u64
    }
}

/// All computed catalog parameters used to build directories and FAT chains.
#[derive(Debug, Clone)]
pub struct FileCatalog {
    pub root_cluster: u32,
    pub cats_cluster: u32,
    pub first_subdir_cluster: u32,
    pub first_file_cluster: u32,
    total_file_clusters: u64,
}

impl FileCatalog {
    pub fn new(geometry: &Geometry) -> Self {
        let root_cluster = 2;
        let cats_cluster = 3;
        let first_subdir_cluster = 4;
        let first_file_cluster = first_subdir_cluster + DIRECTORY_COUNT;
        let total_file_clusters = total_files() as u64 * CLUSTERS_PER_FILE as u64;
        let max_cluster = first_file_cluster as u64 + total_file_clusters;
        let data_capacity = geometry.total_data_clusters();
        assert!(
            max_cluster <= data_capacity + 2,
            "insufficient clusters to map catalog"
        );
        Self {
            root_cluster,
            cats_cluster,
            first_subdir_cluster,
            first_file_cluster,
            total_file_clusters,
        }
    }

    pub const fn files_per_directory(&self) -> u32 {
        FILES_PER_DIRECTORY
    }

    pub const fn directories(&self) -> u32 {
        DIRECTORY_COUNT
    }

    pub const fn clusters_per_file(&self) -> u32 {
        CLUSTERS_PER_FILE
    }

    pub const fn max_file_bytes(&self, geometry: &Geometry) -> u64 {
        geometry.cluster_bytes() * CLUSTERS_PER_FILE as u64
    }

    pub fn cluster_kind(&self, cluster: u32) -> ClusterKind {
        if cluster == self.root_cluster {
            return ClusterKind::Root;
        }
        if cluster == self.cats_cluster {
            return ClusterKind::Cats;
        }
        if cluster >= self.first_subdir_cluster
            && cluster < self.first_subdir_cluster + DIRECTORY_COUNT
        {
            return ClusterKind::Subdirectory {
                dir_index: cluster - self.first_subdir_cluster,
            };
        }
        if cluster >= self.first_file_cluster {
            let relative = cluster - self.first_file_cluster;
            if (relative as u64) < self.total_file_clusters {
                let file_index = relative / CLUSTERS_PER_FILE;
                let cluster_offset = relative % CLUSTERS_PER_FILE;
                let dir_index = file_index / FILES_PER_DIRECTORY;
                let file_number = file_index % FILES_PER_DIRECTORY;
                return ClusterKind::FileData {
                    id: FileId::new(dir_index, file_number),
                    cluster_offset,
                };
            }
        }
        ClusterKind::Free
    }

    pub fn first_cluster_for_file(&self, id: FileId) -> Option<u32> {
        if id.dir_index >= DIRECTORY_COUNT || id.file_index >= FILES_PER_DIRECTORY {
            return None;
        }
        let idx = id.linear_index();
        let start = self.first_file_cluster as u64 + idx * CLUSTERS_PER_FILE as u64;
        Some(start as u32)
    }
}

/// Classification of clusters for directory/material generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterKind {
    Root,
    Cats,
    Subdirectory { dir_index: u32 },
    FileData { id: FileId, cluster_offset: u32 },
    Free,
}

const fn total_files() -> u32 {
    DIRECTORY_COUNT * FILES_PER_DIRECTORY
}

/// Directory description used when synthesizing entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryKind {
    Root,
    Cats,
    Subdirectory { dir_index: u32 },
}

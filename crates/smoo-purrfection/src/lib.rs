#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod dir;
mod fat;
mod geometry;
mod provider;

pub use dir::{FileCatalog, FileId};
pub use geometry::Geometry;
pub use provider::{CatDataProvider, DebugPatternProvider, ProviderError};

use alloc::boxed::Box;
use async_trait::async_trait;
use core::cmp;
use dir::{ClusterKind, DirectoryKind};
use fat::fat_entry;
use geometry::{BlockRegion, ReservedKind};
use smoo_host_core::{BlockSource, BlockSourceError, BlockSourceErrorKind, BlockSourceResult};

const DIR_ENTRY_LEN: usize = 32;
const FAT_ENTRY_LEN: usize = 4;
/// Read-only FAT32 block source populated with procedural cat imagery.
pub struct VirtualFatBlockSource<P> {
    geom: Geometry,
    catalog: FileCatalog,
    provider: P,
}

impl<P> VirtualFatBlockSource<P>
where
    P: CatDataProvider,
{
    /// Create a new virtual block source backed by the provided cat data supplier.
    pub fn new(provider: P) -> Self {
        let geom = Geometry::new();
        let catalog = FileCatalog::new(&geom);
        Self {
            geom,
            catalog,
            provider,
        }
    }

    /// Access the fixed geometry description.
    pub fn geometry(&self) -> &Geometry {
        &self.geom
    }

    /// Access catalog metadata.
    pub fn catalog(&self) -> &FileCatalog {
        &self.catalog
    }

    /// Synchronous helper for tests.
    pub fn read_blocks_sync(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.ensure_aligned(buf.len())?;
        self.ensure_range(lba, buf.len() as u64 / self.block_size() as u64)?;
        let block_size = self.block_size() as usize;
        for (index, chunk) in buf.chunks_mut(block_size).enumerate() {
            self.read_block(lba + index as u64, chunk)?;
        }
        Ok(buf.len())
    }

    fn ensure_aligned(&self, len: usize) -> BlockSourceResult<()> {
        if len % self.block_size() as usize != 0 {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::InvalidInput,
                "buffer length must align to block size",
            ));
        }
        Ok(())
    }

    fn ensure_range(&self, lba: u64, blocks: u64) -> BlockSourceResult<()> {
        if blocks == 0 {
            return Ok(());
        }
        let end = lba
            .checked_add(blocks)
            .ok_or_else(|| BlockSourceError::new(BlockSourceErrorKind::OutOfRange))?;
        if end > self.geom.total_blocks() {
            return Err(BlockSourceError::new(BlockSourceErrorKind::OutOfRange));
        }
        Ok(())
    }

    fn read_block(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<()> {
        match self.geom.region_for_block(lba) {
            BlockRegion::Reserved(kind) => self.fill_reserved(kind, buf),
            BlockRegion::Fat { block_index } => {
                self.fill_fat(block_index, buf);
                Ok(())
            }
            BlockRegion::Data { .. } => self.fill_data_block(lba, buf),
        }
    }

    fn fill_reserved(&self, kind: ReservedKind, buf: &mut [u8]) -> BlockSourceResult<()> {
        match kind {
            ReservedKind::BootSector => self.write_boot_sector(buf),
            ReservedKind::FsInfo => self.write_fsinfo(buf),
            ReservedKind::Other(_) => {
                buf.fill(0);
                Ok(())
            }
        }
    }

    fn write_boot_sector(&self, buf: &mut [u8]) -> BlockSourceResult<()> {
        buf.fill(0);
        buf[0] = 0xEB;
        buf[1] = 0x58;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"SMOOCATS");
        let bps = self.block_size() as u16;
        buf[11..13].copy_from_slice(&bps.to_le_bytes());
        buf[13] = self.geom.blocks_per_cluster() as u8;
        let reserved = self.geom.reserved_blocks() as u16;
        buf[14..16].copy_from_slice(&reserved.to_le_bytes());
        buf[16] = 1; // one FAT
        buf[21] = 0xF8; // media descriptor
        let total_sectors = self.geom.total_blocks() as u32;
        buf[32..36].copy_from_slice(&total_sectors.to_le_bytes());
        let sectors_per_fat = self.geom.fat_block_count() as u32;
        buf[36..40].copy_from_slice(&sectors_per_fat.to_le_bytes());
        buf[44..48].copy_from_slice(&self.catalog.root_cluster.to_le_bytes());
        buf[48..50].copy_from_slice(&(1u16).to_le_bytes()); // fsinfo
        buf[50..52].copy_from_slice(&(6u16).to_le_bytes()); // backup boot sector
        buf[64] = 0x80; // drive number
        buf[66] = 0x29; // boot signature
        buf[67..71].copy_from_slice(&0x20240101u32.to_le_bytes());
        buf[71..82].copy_from_slice(b"SMOOCATS   ");
        buf[82..90].copy_from_slice(b"FAT32   ");
        let sig = buf.len() - 2;
        buf[sig..].copy_from_slice(&0xAA55u16.to_le_bytes());
        Ok(())
    }

    fn write_fsinfo(&self, buf: &mut [u8]) -> BlockSourceResult<()> {
        buf.fill(0);
        buf[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
        buf[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
        buf[488..492].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf[492..496].copy_from_slice(&self.catalog.first_file_cluster.to_le_bytes());
        buf[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
        Ok(())
    }

    fn fill_fat(&self, block_index: u64, buf: &mut [u8]) {
        let entries_per_block = buf.len() / FAT_ENTRY_LEN;
        let base_entry = block_index * entries_per_block as u64;
        for i in 0..entries_per_block {
            let cluster = base_entry + i as u64;
            let value = if cluster > u32::MAX as u64 {
                0
            } else {
                fat_entry(&self.catalog, cluster as u32)
            };
            buf[i * FAT_ENTRY_LEN..(i + 1) * FAT_ENTRY_LEN].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn fill_data_block(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<()> {
        let (cluster, block_in_cluster) = self
            .geom
            .cluster_for_data_block(lba)
            .ok_or_else(|| BlockSourceError::new(BlockSourceErrorKind::OutOfRange))?;
        match self.catalog.cluster_kind(cluster) {
            ClusterKind::Root => {
                self.write_directory_block(DirectoryKind::Root, block_in_cluster, buf)
            }
            ClusterKind::Cats => {
                self.write_directory_block(DirectoryKind::Cats, block_in_cluster, buf)
            }
            ClusterKind::Subdirectory { dir_index } => self.write_directory_block(
                DirectoryKind::Subdirectory { dir_index },
                block_in_cluster,
                buf,
            ),
            ClusterKind::FileData { id, cluster_offset } => {
                self.write_file_data(id, cluster_offset, block_in_cluster, buf)
            }
            ClusterKind::Free => {
                buf.fill(0);
                Ok(())
            }
        }
    }

    fn write_directory_block(
        &self,
        kind: DirectoryKind,
        block_in_cluster: u32,
        buf: &mut [u8],
    ) -> BlockSourceResult<()> {
        let entries_per_block = buf.len() / DIR_ENTRY_LEN;
        let start_entry = block_in_cluster * entries_per_block as u32;
        for i in 0..entries_per_block {
            let entry_index = start_entry + i as u32;
            let slot = &mut buf[i * DIR_ENTRY_LEN..(i + 1) * DIR_ENTRY_LEN];
            if !self.write_directory_entry(kind, entry_index, slot)? {
                slot.fill(0);
            }
        }
        Ok(())
    }

    fn write_directory_entry(
        &self,
        kind: DirectoryKind,
        entry_index: u32,
        buf: &mut [u8],
    ) -> BlockSourceResult<bool> {
        match kind {
            DirectoryKind::Root => self.write_root_entry(entry_index, buf),
            DirectoryKind::Cats => self.write_cats_entry(entry_index, buf),
            DirectoryKind::Subdirectory { dir_index } => {
                self.write_subdirectory_entry(dir_index, entry_index, buf)
            }
        }
    }

    fn write_root_entry(&self, entry_index: u32, buf: &mut [u8]) -> BlockSourceResult<bool> {
        let entry = match entry_index {
            0 => Some(DirEntry::dot(self.catalog.root_cluster)),
            1 => Some(DirEntry::dotdot(self.catalog.root_cluster)),
            2 => Some(DirEntry::directory(
                name_bytes(b"CATS"),
                self.catalog.cats_cluster,
            )),
            _ => None,
        };
        if let Some(entry) = entry {
            entry.write(buf);
            return Ok(true);
        }
        Ok(false)
    }

    fn write_cats_entry(&self, entry_index: u32, buf: &mut [u8]) -> BlockSourceResult<bool> {
        if entry_index == 0 {
            DirEntry::dot(self.catalog.cats_cluster).write(buf);
            return Ok(true);
        }
        if entry_index == 1 {
            DirEntry::dotdot(self.catalog.root_cluster).write(buf);
            return Ok(true);
        }
        let slot = entry_index - 2;
        if slot >= self.catalog.directories() {
            return Ok(false);
        }
        let name = directory_short_name(slot);
        let cluster = self.catalog.first_subdir_cluster + slot;
        DirEntry::directory(name, cluster).write(buf);
        Ok(true)
    }

    fn write_subdirectory_entry(
        &self,
        dir_index: u32,
        entry_index: u32,
        buf: &mut [u8],
    ) -> BlockSourceResult<bool> {
        if entry_index == 0 {
            DirEntry::dot(self.catalog.first_subdir_cluster + dir_index).write(buf);
            return Ok(true);
        }
        if entry_index == 1 {
            DirEntry::dotdot(self.catalog.cats_cluster).write(buf);
            return Ok(true);
        }
        let file_slot = entry_index - 2;
        if file_slot >= self.catalog.files_per_directory() {
            return Ok(false);
        }
        let id = FileId::new(dir_index, file_slot);
        let cluster = self.catalog.first_cluster_for_file(id).ok_or_else(|| {
            BlockSourceError::with_message(BlockSourceErrorKind::Other, "invalid file mapping")
        })?;
        let len = self.provider.file_len(id);
        if len > self.catalog.max_file_bytes(&self.geom) {
            return Err(BlockSourceError::with_message(
                BlockSourceErrorKind::Unsupported,
                "file exceeds reserved cluster chain",
            ));
        }
        let size = cmp::min(len, u32::MAX as u64) as u32;
        let entry = DirEntry::file(file_short_name(id), *b"JPG", cluster, size);
        entry.write(buf);
        Ok(true)
    }

    fn write_file_data(
        &self,
        id: FileId,
        cluster_offset: u32,
        block_in_cluster: u32,
        buf: &mut [u8],
    ) -> BlockSourceResult<()> {
        let offset = self.file_offset(cluster_offset, block_in_cluster);
        self.provider
            .read_at(id, offset, buf)
            .map_err(|_| BlockSourceError::new(BlockSourceErrorKind::Io))
    }

    fn file_offset(&self, cluster_offset: u32, block_in_cluster: u32) -> u64 {
        let cluster_bytes = self.geom.cluster_bytes();
        let block_bytes = self.block_size() as u64;
        cluster_offset as u64 * cluster_bytes + block_in_cluster as u64 * block_bytes
    }
}

impl<P> VirtualFatBlockSource<P>
where
    P: CatDataProvider,
{
    fn block_size(&self) -> u32 {
        self.geom.block_size()
    }
}

#[async_trait]
impl<P> BlockSource for VirtualFatBlockSource<P>
where
    P: CatDataProvider + Send + Sync,
{
    fn block_size(&self) -> u32 {
        self.geom.block_size()
    }

    async fn total_blocks(&self) -> BlockSourceResult<u64> {
        Ok(self.geom.total_blocks())
    }

    async fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> BlockSourceResult<usize> {
        self.read_blocks_sync(lba, buf)
    }

    async fn write_blocks(&self, _lba: u64, _buf: &[u8]) -> BlockSourceResult<usize> {
        Err(BlockSourceError::with_message(
            BlockSourceErrorKind::Unsupported,
            "virtual FAT is read-only",
        ))
    }
}

struct DirEntry {
    short_name: [u8; 8],
    extension: [u8; 3],
    attr: u8,
    cluster: u32,
    size: u32,
}

impl DirEntry {
    fn directory(short_name: [u8; 8], cluster: u32) -> Self {
        Self {
            short_name,
            extension: [b' '; 3],
            attr: 0x10,
            cluster,
            size: 0,
        }
    }

    fn file(short_name: [u8; 8], extension: [u8; 3], cluster: u32, size: u32) -> Self {
        Self {
            short_name,
            extension,
            attr: 0x20,
            cluster,
            size,
        }
    }

    fn dot(cluster: u32) -> Self {
        Self::directory(padded_name(b"."), cluster)
    }

    fn dotdot(cluster: u32) -> Self {
        Self::directory(padded_name(b".."), cluster)
    }

    fn write(&self, buf: &mut [u8]) {
        buf.fill(0);
        buf[..8].copy_from_slice(&self.short_name);
        buf[8..11].copy_from_slice(&self.extension);
        buf[11] = self.attr;
        let cluster_high = (self.cluster >> 16) as u16;
        let cluster_low = (self.cluster & 0xFFFF) as u16;
        buf[20..22].copy_from_slice(&cluster_high.to_le_bytes());
        buf[26..28].copy_from_slice(&cluster_low.to_le_bytes());
        buf[28..32].copy_from_slice(&self.size.to_le_bytes());
    }
}

fn padded_name(name: &[u8]) -> [u8; 8] {
    let mut out = [b' '; 8];
    for (idx, byte) in name.iter().enumerate().take(8) {
        out[idx] = byte.to_ascii_uppercase();
    }
    out
}

fn name_bytes(name: &[u8]) -> [u8; 8] {
    padded_name(name)
}

fn directory_short_name(index: u32) -> [u8; 8] {
    let mut name = [b' '; 8];
    write_digits(index, &mut name[..4]);
    name
}

fn file_short_name(id: FileId) -> [u8; 8] {
    let mut name = [b' '; 8];
    name[0] = b'C';
    write_digits(id.dir_index, &mut name[1..5]);
    write_digits(id.file_index, &mut name[5..8]);
    name
}

fn write_digits(value: u32, out: &mut [u8]) {
    if out.is_empty() {
        return;
    }
    let mut v = value;
    for idx in (0..out.len()).rev() {
        let digit = (v % 10) as u8;
        out[idx] = b'0' + digit;
        v /= 10;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn source() -> VirtualFatBlockSource<DebugPatternProvider> {
        VirtualFatBlockSource::new(DebugPatternProvider::default())
    }

    fn read_block_bytes<P: CatDataProvider>(src: &VirtualFatBlockSource<P>, lba: u64) -> Vec<u8> {
        let mut block = vec![0u8; src.block_size() as usize];
        src.read_blocks_sync(lba, &mut block).unwrap();
        block
    }

    fn entry_slice<'a>(block: &'a [u8], index: usize) -> &'a [u8] {
        let start = index * DIR_ENTRY_LEN;
        &block[start..start + DIR_ENTRY_LEN]
    }

    fn extract_short_name(entry: &[u8]) -> [u8; 8] {
        let mut out = [0u8; 8];
        out.copy_from_slice(&entry[..8]);
        out
    }

    fn extract_extension(entry: &[u8]) -> [u8; 3] {
        let mut out = [0u8; 3];
        out.copy_from_slice(&entry[8..11]);
        out
    }

    fn extract_attr(entry: &[u8]) -> u8 {
        entry[11]
    }

    fn extract_cluster(entry: &[u8]) -> u32 {
        let high = u16::from_le_bytes([entry[20], entry[21]]) as u32;
        let low = u16::from_le_bytes([entry[26], entry[27]]) as u32;
        (high << 16) | low
    }

    fn extract_size(entry: &[u8]) -> u32 {
        u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]])
    }

    #[test]
    fn boot_sector_signature() {
        let src = source();
        let block = read_block_bytes(&src, 0);
        assert_eq!(&block[3..11], b"SMOOCATS");
        assert_eq!(&block[71..82], b"SMOOCATS   ");
        assert_eq!(&block[block.len() - 2..], b"\x55\xAA");
        assert_eq!(
            u16::from_le_bytes([block[11], block[12]]),
            src.block_size() as u16
        );
        assert_eq!(block[13], src.geometry().blocks_per_cluster() as u8);
    }

    #[test]
    fn fat_entries_cover_root_and_files() {
        let src = source();
        let geom = src.geometry();
        let entries_per_block = src.block_size() as usize / FAT_ENTRY_LEN;
        let fat_start = geom.fat_start_block();
        let first_block = read_block_bytes(&src, fat_start);
        assert_eq!(
            u32::from_le_bytes(first_block[0..4].try_into().unwrap()),
            0x0FFFFFF8
        );
        assert_eq!(
            u32::from_le_bytes(first_block[4..8].try_into().unwrap()),
            0xFFFFFFFF
        );
        let root_entry = u32::from_le_bytes(
            first_block[2 * FAT_ENTRY_LEN..3 * FAT_ENTRY_LEN]
                .try_into()
                .unwrap(),
        );
        assert_eq!(root_entry & 0x0FFFFFFF, 0x0FFFFFFF);

        let id = FileId::new(0, 0);
        let first_cluster = src.catalog().first_cluster_for_file(id).unwrap();
        let block_index = first_cluster as usize / entries_per_block;
        let block = read_block_bytes(&src, fat_start + block_index as u64);
        let entry_index = first_cluster as usize % entries_per_block;
        let entry = u32::from_le_bytes(
            block[entry_index * FAT_ENTRY_LEN..(entry_index + 1) * FAT_ENTRY_LEN]
                .try_into()
                .unwrap(),
        );
        assert_eq!(entry, first_cluster + 1);
    }

    #[test]
    fn directory_layout_contains_expected_entries() {
        let src = source();
        let geom = src.geometry();
        let catalog = src.catalog();
        let root_block = read_block_bytes(
            &src,
            geom.first_block_of_cluster(catalog.root_cluster).unwrap(),
        );
        let dot = entry_slice(&root_block, 0);
        assert_eq!(extract_short_name(dot), *b".       ");
        assert_eq!(extract_attr(dot), 0x10);
        let cats_entry = entry_slice(&root_block, 2);
        assert_eq!(extract_short_name(cats_entry), name_bytes(b"CATS"));
        assert_eq!(extract_cluster(cats_entry), catalog.cats_cluster);

        let cats_block = read_block_bytes(
            &src,
            geom.first_block_of_cluster(catalog.cats_cluster).unwrap(),
        );
        let first_dir = entry_slice(&cats_block, 2);
        assert_eq!(extract_short_name(first_dir), directory_short_name(0));
        assert_eq!(extract_cluster(first_dir), catalog.first_subdir_cluster);

        let dir_index = catalog.directories() - 1;
        let entries_per_block = src.block_size() as usize / DIR_ENTRY_LEN;
        let entry_idx = (dir_index + 2) as usize;
        let block_offset = entry_idx / entries_per_block;
        let entry_offset = entry_idx % entries_per_block;
        let block = read_block_bytes(
            &src,
            geom.first_block_of_cluster(catalog.cats_cluster).unwrap() + block_offset as u64,
        );
        let last_dir = entry_slice(&block, entry_offset);
        assert_eq!(
            extract_short_name(last_dir),
            directory_short_name(dir_index)
        );
    }

    #[test]
    fn file_entry_and_data_match_provider() {
        let src = source();
        let geom = src.geometry();
        let catalog = src.catalog();
        let dir_index = 5;
        let dir_cluster = catalog.first_subdir_cluster + dir_index;
        let dir_block = read_block_bytes(&src, geom.first_block_of_cluster(dir_cluster).unwrap());
        let first_file_entry = entry_slice(&dir_block, 2);
        assert_eq!(
            extract_short_name(first_file_entry),
            file_short_name(FileId::new(dir_index, 0))
        );
        assert_eq!(extract_extension(first_file_entry), *b"JPG");
        assert_eq!(
            extract_size(first_file_entry),
            DebugPatternProvider::default().file_len(FileId::new(dir_index, 0)) as u32
        );

        let file_cluster = catalog
            .first_cluster_for_file(FileId::new(dir_index, 0))
            .unwrap();
        let data_block = read_block_bytes(&src, geom.first_block_of_cluster(file_cluster).unwrap());
        let provider = DebugPatternProvider::default();
        let expected = expected_pattern(provider, FileId::new(dir_index, 0), 0, data_block.len());
        assert_eq!(data_block, expected);
    }

    fn expected_pattern(
        provider: DebugPatternProvider,
        id: FileId,
        offset: u64,
        len: usize,
    ) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let limit = provider.file_len(id);
        for (idx, byte) in out.iter_mut().enumerate() {
            let absolute = offset + idx as u64;
            if absolute >= limit {
                *byte = 0;
                continue;
            }
            let base = ((id.dir_index as u64) << 32) | id.file_index as u64;
            *byte = base.wrapping_add(absolute) as u8;
        }
        out
    }
}

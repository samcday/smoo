use futures::executor::block_on;
use smoo_host_core::BlockSource;
use smoo_purrfection::{CatDataProvider, DebugPatternProvider, FileId, VirtualFatBlockSource};

fn expected_pattern(id: FileId, offset: u64, len: usize) -> Vec<u8> {
    let provider = DebugPatternProvider::default();
    let mut buf = vec![0u8; len];
    let limit = provider.file_len(id);
    for (i, byte) in buf.iter_mut().enumerate() {
        let absolute = offset + i as u64;
        if absolute >= limit {
            *byte = 0;
            continue;
        }
        let base = ((id.dir_index as u64) << 32) | id.file_index as u64;
        *byte = base.wrapping_add(absolute) as u8;
    }
    buf
}

#[test]
fn block_source_reads_multiple_regions() {
    let source = VirtualFatBlockSource::new(DebugPatternProvider::default());
    let block_size = source.block_size() as usize;
    let mut block = vec![0u8; block_size];

    block_on(source.read_blocks(0, &mut block)).expect("boot sector");
    assert_eq!(&block[3..11], b"SMOOCATS");

    let fat_lba = source.geometry().fat_start_block();
    block_on(source.read_blocks(fat_lba, &mut block)).expect("fat");
    assert_eq!(
        u32::from_le_bytes(block[0..4].try_into().unwrap()),
        0x0FFFFFF8
    );

    let root_cluster = source.catalog().root_cluster;
    let root_lba = source
        .geometry()
        .first_block_of_cluster(root_cluster)
        .unwrap();
    block_on(source.read_blocks(root_lba, &mut block)).expect("root dir");
    assert_eq!(&block[64..72], b"CATS    ");

    let id = FileId::new(2, 3);
    let cluster = source.catalog().first_cluster_for_file(id).unwrap();
    let lba = source.geometry().first_block_of_cluster(cluster).unwrap();
    block_on(source.read_blocks(lba, &mut block)).expect("file data");
    assert_eq!(block, expected_pattern(id, 0, block_size));
}

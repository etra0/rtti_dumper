use memory_rs::internal::memory_region::MemoryRegion;
use serde::Serialize;
use std::ffi::CStr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// This struct will contain the basic information about the RTTI when
/// the scan_aob gets a match.
#[derive(Serialize, Clone)]
pub struct RTTIMatch {
    /// Name of the RTTI.
    pub name: String,

    /// Address of the string found - 0x10
    pub addr: usize,

    /// Possible matches containing the rtti information
    pub possible_matches: Vec<usize>,
}

impl std::fmt::Display for RTTIMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\t+{:x}\t{:x?}",
            self.name, self.addr, self.possible_matches
        )
    }
}

pub fn scan_rtti(
    rtti_addr: usize,
    region: &Arc<MemoryRegion>,
    total_revised: &Arc<AtomicUsize>,
    total_scans: &Arc<AtomicUsize>,
) -> Result<Option<RTTIMatch>, Box<dyn std::error::Error>> {
    let name = {
        let lossy = unsafe { CStr::from_ptr(rtti_addr as _) };
        let name = String::from(lossy.to_string_lossy());
        name
    };

    // We don't need to store lambda functions
    if name.contains("lambda") {
        total_revised.fetch_add(1, Ordering::Relaxed);
        return Ok(None);
    }

    let relative_rtti_info: u32 = (rtti_addr - 0x10 - region.start_address) as u32;

    let matches = region.scan_aligned_value(relative_rtti_info)?;
    total_scans.fetch_add(1, Ordering::Relaxed);

    let mut possible_matches = vec![];
    for m in matches {
        let results = region.scan_aligned_value(m - 0xC)?;
        possible_matches.extend_from_slice(&results);
        total_scans.fetch_add(1, Ordering::Relaxed);
    }

    let possible_matches = possible_matches
        .iter()
        .map(|&x| x - region.start_address)
        .collect();

    let rtti = RTTIMatch {
        name,
        addr: rtti_addr - region.start_address,
        possible_matches,
    };
    total_revised.fetch_add(1, Ordering::Relaxed);

    Ok(Some(rtti))
}

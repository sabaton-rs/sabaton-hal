/// Hardware abstracion and data-structure for Software Updates
/// 
/*
 * Copyright Sabaton Systems LLP, 2022 - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */


use std::{path::{Path, PathBuf}, io::Write, fs::File};
use serde_json;
use uuid::Uuid;
use semver::Version;
use serde::{Deserialize, Serialize};
use crate::digest;


/// Trait to map part names with files. This trait is used by the UpdateManager to map the 
/// part name to the actual partition on the device. The implementor of this trait
pub trait UpdateMapper {
    /// Open a part for write. This is the destination partition
    /// where data will be written.
    fn get_destination_for_part(&self, part: &Part) -> Result<Box<dyn Write>, UpdateMapperError>;

    ///Open a part for read. This is used as the reference for
    /// delta calculation. Opens the file for write and returns the
    /// handle
    fn get_reference_for_part(&self, part: &Part) -> Result<File, UpdateMapperError>;
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum UpdateMapperError {
    #[error("Unidentifed part in package")]
    UnidentifiedPart,
    #[error("IO Error")]
    IOError(#[from] std::io::Error),
}

pub const OTA_PACKAGE_NAME : &str = "package.zst";

/// Device Manifest for an update
#[derive(Deserialize, Serialize)]
pub struct Device {
    name : String,
    id : Uuid,
    version : Version,
    full_image : String,
    sha256sum: String,
    size : u64,
    parts : Vec<Part>,
}

impl Device {
    pub fn new(name: String, id: Uuid, version : Version, full_image: String) -> Self {
        Device { name, id, version, full_image, parts: Vec::new() , sha256sum:String::new(), size: 0}        
    }

    pub fn from_file(path : &Path) -> Result<Self,std::io::Error> {
        let toml = String::from_utf8(std::fs::read(path)?).expect("Error converting string");
        let device : Self = serde_json::from_str(&toml).map_err(|_e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid data")
        })?;
        Ok(device)
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn full_image(&self) -> &str {
        self.full_image.as_str()
    }

    pub fn parts(&self) -> &[Part] {
        self.parts.as_slice()
    }

    pub fn find_part(&self, name:&str) -> Option<&Part> {
        self.parts.iter().find(|p| p.name() == name)
    }

    pub fn add_part(&mut self, part : Part) {
        self.parts.push(part)
    } 

    pub fn to_file(&self,path: &Path) -> Result<(),std::io::Error> {
        let toml = serde_json::to_string(self).unwrap();
        std::fs::write(path, toml.as_bytes())?;
        Ok(())
    }

    pub fn compute_checksums(&mut self, package_folder: &Path) {

        let full_image_path = package_folder.join(self.full_image());
        self.sha256sum = digest::checksum(&full_image_path);
        self.size = std::fs::metadata(full_image_path).unwrap().len();

        for part in &mut self.parts {
            let file_path = package_folder.join(&part.filename);
            part.sha256sum = digest::checksum(&file_path);
            part.size = std::fs::metadata(&file_path).unwrap().len();
        }
    }

    pub fn validate_checksums(&self,package_folder: &Path) -> Result<(),PathBuf> {
        for part in &self.parts {
            let file_path = package_folder.join(&part.filename);
            if part.sha256sum != digest::checksum(&file_path) {
                return Err(file_path)
            }
        }
        Ok(())
    }
}


/// A part of the update.  A part usually refers to a partition
/// that needs to be updated, but it can also refer to any other 
/// part of an update like for example firmware that belongs to another
/// microcontroller that is connected to the main processor.
#[derive(Deserialize, Serialize)]
pub struct Part {
    ///name of the part
    pub name : String,
    /// version of the part
    pub version : Version,
    pub filename : String,
    pub gpt_id : Uuid,
    pub partitions : Vec<String>,
    pub sha256sum: String,
    pub size : u64,

}

impl Part {
    pub fn new(name: String, version : Version, filename: String, gpt_id: Uuid, sha256sum: String) -> Self {
        Part { name, version, filename, gpt_id, partitions: Vec::new(),sha256sum, size: 0}
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn filename(&self) -> &str {
        self.filename.as_str()
    }

    pub fn gpt_id(&self) -> &Uuid {
        &self.gpt_id
    }

    pub fn  partitions(&self) -> &[String] {
        self.partitions.as_slice()
    }

    pub fn add_partition(&mut self, partition: String) {
        self.partitions.push(partition)
    }

    pub fn checksum(&self) -> &str {
        &self.sha256sum
    }
}


#[derive(Debug,Deserialize, Serialize)]
pub struct DeltaPart {
    // If a delta is provided, this is the part name of the 
    // old version
    pub old_part : Option<String>,
    pub old_sha256_sum : Option<String>,
    // the new part name.
    pub new_part : String,
    pub new_sha256_sum : String,
    pub partitions : Vec<String>,
    // the name of the file with the delta contents.
    pub patch : String,
    pub patch_sha256_sum : String,
}

impl DeltaPart {
    pub fn expected_checksum(&self) -> &str {
        self.new_sha256_sum.as_str()
    }

    pub fn name(&self) -> &str {
        self.new_part.as_str()
    }
}

#[derive(Debug,Deserialize, Serialize)]
pub struct UpdatePackage {
    // the device id this package is meant for
    pub device_id : Uuid,
    // the target version this package is meant for
    pub version : Version,
    // If this is a delta package, the previous version it is meant for
    pub previous_version : Option<Version>,
    // The file that contains the archive of parts
    pub file : String,
    // The checksum of the archive
    pub sha256sum : String,
    // list of parts
    pub parts : Vec<DeltaPart>,

}

impl UpdatePackage {
    pub fn add_part(&mut self, part : DeltaPart) {
        self.parts.push(part);
    }

    pub fn find_part(&self, name:&str) -> Option<&DeltaPart> {
        self.parts.iter().find(|p| p.new_part == name)
    }

    pub fn from_file(path:&Path) -> Result<Self,std::io::Error> {
        let file = std::fs::File::open(path)?;
        let manifest : Self = serde_json::from_reader(file)?;
        Ok(manifest)
    }

}

#[derive(Deserialize, Serialize)]
/// This is the information stored in the root of the filesytem. It is injected by the builder automatically
pub struct FsVersionManifest {
    /// The device identifier
    pub device_id : Uuid,
    /// Version of the device this part belongs to
    pub device_version : Version,
    /// the GPT GUID of the storage device where this part belongs.
    /// If the device has only one storage, this may be the same as device_id
    pub gpt_guid : Uuid,
    /// The part name
    pub part_name :String,
    /// Part version
    pub part_version : Version,
}

impl FsVersionManifest {

    pub fn from_file(path:&Path) -> Result<Self,std::io::Error> {
        let file = std::fs::File::open(path)?;
        let manifest : Self = serde_json::from_reader(file)?;
        Ok(manifest)
    }
    pub fn device_id(&self) -> &Uuid {
        &self.device_id
    }

    pub fn device_version(&self) -> &Version {
        &self.device_version
    }
}
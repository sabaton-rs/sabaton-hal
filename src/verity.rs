/*
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */


use std::{path::{PathBuf, Path}, io::{Write, Seek, Read}};
use ring::{signature, rand};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SHA256_SIZE: usize = ring::digest::SHA256_OUTPUT_LEN;
pub const VERITY_HEADER_VERSION : u32 = 1;
const VERITY_HEADER_MAGIC : u32 = 0xb001b001u32;
const VERITY_HEADER_MAX_SERIALIZED_LEN : usize = (32*1024) - 268;
pub type Sha256Digest = [u8; SHA256_SIZE];
pub type Salt = Sha256Digest;

pub struct VerityPartitionHeader {
    tables : Vec<VerityTable>,
}

#[derive(Deserialize, Serialize)]
pub struct VerityTable {
    pub data_device : PathBuf,
    pub hash_device : PathBuf,
    pub data_block_size : u32,
    pub hash_block_size : u32,
    /// Number of hash blocks for this device
    pub num_blocks : u32,
    /// Offset of the hash blocks of this device from the start
    /// of the block where the hash is stored.
    pub hash_start : u32,
    pub algorithm : String,
    pub digest: Sha256Digest,
    pub salt : Sha256Digest,
    pub restart_on_corruption : bool,
    pub panic_on_corruption : bool,
    pub check_at_most_once : bool
}


/*
   Format of vbmeta partition
   magic   : u32,   0xb001b001u32   
   version : u32,   Version 1
   signature : [u8;256] 
   table_data_len : u32,  // Length in bytes of table data
   table_data_bytes .... until 32K boundary.

   Minimum size = 4 + 4 + 4 + 256 + 4

*/

impl  VerityPartitionHeader {

    pub fn new() -> Self {
        VerityPartitionHeader { tables:  Vec::new() }
    }

    pub fn add_table(&mut self, table : VerityTable) {
        self.tables.push(table)
    }
    
    pub fn get_entry(&self, data_device: &Path) -> Option<&VerityTable> {
        self.tables.iter().find_map(|e|{
            if e.data_device == data_device {
                Some(e)
            } else {
                None
            }
        })
    }

    pub fn create_from_reader<T:Read>( mut reader : T, public_key : &[u8]) -> Result<Self, VerityError> {
        let mut temp_buf = vec![0u8;4];
        reader.read_exact(&mut temp_buf)
            .map_err(|e|{
                VerityError::Os { context: "Reading magic".to_owned(), error: e }
            })?;

        let magic = u32::from_ne_bytes([temp_buf[0], temp_buf[1], temp_buf[2], temp_buf[3]]);
        if magic != VERITY_HEADER_MAGIC {
            log::error!("Bad verity header magic");
            return Err(VerityError::InvalidHeader);
        }

        reader.read_exact(&mut temp_buf)
            .map_err(|e|{
                VerityError::Os { context: "Reading version".to_owned(), error: e }
            })?;
        
        let version = u32::from_ne_bytes([temp_buf[0], temp_buf[1], temp_buf[2], temp_buf[3]]);
        if version != VERITY_HEADER_VERSION {
            log::error!("Bad verity header version");
            return Err(VerityError::InvalidHeader);
        }

        let mut signature = vec![0u8;256];
        reader.read_exact(&mut signature)
            .map_err(|e|{
                VerityError::Os { context: "Reading signature".to_owned(), error: e }
            })?;

        reader.read_exact(&mut temp_buf)
        .map_err(|e|{
            VerityError::Os { context: "Reading table length".to_owned(), error: e }
        })?;
        let table_data_length = u32::from_ne_bytes([temp_buf[0], temp_buf[1], temp_buf[2], temp_buf[3]]) as usize;
        if table_data_length > VERITY_HEADER_MAX_SERIALIZED_LEN {
            log::error!("Table cannot be more than 32K");
            return Err(VerityError::InvalidHeader)
        } 

        let mut table_data = vec![0u8;table_data_length];
        reader.read_exact(&mut table_data)
        .map_err(|e|{
            VerityError::Os { context: "Reading table data".to_owned(), error: e }
        })?;

        // verify signature before construction
        let public_key = signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,public_key);

        public_key.verify(&table_data, &signature)
            .map_err(|e|{
                log::error!("Key verification failed: {}", e);
                VerityError::SignatureInvalid
            })?;
        
        // signature ok, safe to deserialize table
        let tables: Vec<VerityTable> = bincode::deserialize(&table_data)
            .map_err(|_e| {
                log::error!("Deserialization failed");
                VerityError::InvalidHeader
            })?;
        
        Ok(
            Self {
                tables,
            }
        )
    }

    #[deprecated]
    pub fn create_from(data: &[u8], public_key : &[u8]) -> Result<Self, VerityError> {
        
        if data.len() < 268 {
            Err(VerityError::InvalidHeader)
        } else {
            let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            if magic != VERITY_HEADER_MAGIC {
                log::error!("Bad verity header magic");
                return Err(VerityError::InvalidHeader)
            }
            let version = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]);
            if version != VERITY_HEADER_VERSION {

            }
            let signature = &data[8..8+256];
            let table_data_length = u32::from_ne_bytes([data[264], data[265], data[266], data[267]]) as usize;
            if table_data_length > VERITY_HEADER_MAX_SERIALIZED_LEN {
                log::error!("Table cannot be more than 32K");
                return Err(VerityError::InvalidHeader)
            } 
            let table_data = &data[268..268+table_data_length]; 

            // verify signature before construction
            let public_key = signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256,public_key);

            public_key.verify(table_data, signature)
                .map_err(|e|{
                    log::error!("Key verification failed: {}", e);
                    VerityError::SignatureInvalid
                })?;
            
            // signature ok, safe to deserialize table
            let tables: Vec<VerityTable> = bincode::deserialize(table_data)
                .map_err(|_e| {
                    log::error!("Deserialization failed");
                    VerityError::InvalidHeader
                })?;
            
            Ok(
                Self {
                    tables,
                }
            )

        }
    }

    pub fn write<T: Write>(&self,w : &mut T, key_pair: &signature::RsaKeyPair) -> Result<(), VerityError> {

        let serialized: Vec<u8> = bincode::serialize(&self.tables).unwrap();
        if serialized.len() > VERITY_HEADER_MAX_SERIALIZED_LEN {
            log::error!("Table too long");
            return Err(VerityError::SignatureInvalid)
        }

        let rng = rand::SystemRandom::new();
        let mut signature = [0u8; 256];
        key_pair
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &rng,
                &serialized,
                &mut signature,
            )
            .map_err(|_e| {
                log::error!("Cannot sign verity table");
                VerityError::CryptoError
            })?;

        let length : u32 = serialized.len() as u32;
    

        let mut raw_sb: Vec<u8> = vec![];
        raw_sb.extend(VERITY_HEADER_MAGIC.to_ne_bytes()); // magic
        raw_sb.extend(VERITY_HEADER_VERSION.to_ne_bytes()); 
        raw_sb.extend(signature);
        raw_sb.extend(length.to_ne_bytes()); 
        raw_sb.extend(serialized); 

        w.write_all(&mut raw_sb)
            .map_err(|e| {
                VerityError::Os { context: "unable to write verity data".to_owned(), error: e }
            })?;

        Ok(())
    }
}


#[derive(Error, Debug)]
pub enum VerityError {
    #[error("Unable to Sign")]
    CryptoError,
    #[error("invalid verity header")]
    InvalidHeader,
    #[error("unsupported verity version {0}")]
    UnsupportedVersion(u32),
    #[error("unsupported verity algorithm")]
    UnsupportedAlgorithm(),
    #[error("error generating hash tree: {0}")]
    HashTree(String),
    #[error("error creating valid uuid")]
    Uuid,
    #[error("Signature invalid")]
    SignatureInvalid,
    #[error("IO error: {context}")]
    Os {
        context: String,
        #[source]
        error: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use ring::signature::KeyPair;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_write_and_read() {

        let table = VerityTable {
            data_device: PathBuf::new().join("system"),
            hash_device: PathBuf::new().join("system"),
            data_block_size: 512,
            hash_block_size: 512,
            num_blocks: 10,
            hash_start: 32*1024,
            algorithm: String::from("sha"),
            digest: [0u8;32],
            salt: [0u8;32],
            restart_on_corruption: false,
            panic_on_corruption: false,
            check_at_most_once: true,
        };

        let table2 = VerityTable {
            data_device : PathBuf::new().join("data"),
            hash_device: PathBuf::new().join("data"),
            data_block_size: 512,
            hash_block_size: 512,
            num_blocks: 10,
            hash_start: 32*1024,
            algorithm: String::from("sha"),
            digest: [0u8;32],
            salt: [0u8;32],
            restart_on_corruption: false,
            panic_on_corruption: false,
            check_at_most_once: true,
        };

        let mut header = VerityPartitionHeader::new();
        header.add_table(table);
        header.add_table(table2);

        let t = header.get_entry(Path::new("data")).unwrap();
        assert_eq!(t.data_device,Path::new("data"));

        let _rng = rand::SystemRandom::new();

        let key_data = std::fs::read("testdata/verity_rsa-2048-private-key.pk8").unwrap();

        let key_pair = ring::signature::RsaKeyPair::from_pkcs8(&key_data)
            .unwrap();

        let mut outbuf = vec![0u8;32*1024];
        let mut slice = outbuf.as_mut_slice();

        header.write(&mut slice, &key_pair).unwrap();

        let public_key = key_pair.public_key().as_ref();

        //println!("buffer:{:?}",outbuf);

        let header = VerityPartitionHeader::create_from_reader(&*outbuf, public_key).unwrap();
        let t = header.get_entry(Path::new("data")).unwrap();
        assert_eq!(t.data_device,Path::new("data"));

        let slice = outbuf.as_mut_slice();
        let header = VerityPartitionHeader::create_from(slice, public_key).unwrap();
        let t = header.get_entry(Path::new("data")).unwrap();
        assert_eq!(t.data_device,Path::new("data"));


        // lets try to corrupt the data
        slice[278] = 0xff;

        if let Ok(_) = VerityPartitionHeader::create_from(&slice, public_key) {
            panic!("This should fail!");
        }

       
        
        // lets try to corrupt the data
        slice[278] = 0xff;

        if let Ok(_) = VerityPartitionHeader::create_from(&slice, public_key) {
            panic!("This should fail!");
        }
    }

}
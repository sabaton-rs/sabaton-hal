/// Interface to communicate with the bootloader
pub trait BootControl {
    /// Initialize the HAL interface. Will be called once
    fn initialize(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }

    /// Get the number of supported slots.
    fn number_of_slots(&self) -> Result<usize, std::io::Error>;

    /// Return the current slot index
    fn current_slot(&self) -> Result<usize, std::io::Error>;

    /// Notify the bootloader that we have successfully
    /// booted from the current slot
    fn set_boot_successful(&mut self) -> Result<(), std::io::Error>;

    /// Mark the provided slot as the active slot. The bootloader must
    /// use this slot to boot the next time
    fn set_active_slot(&mut self, slot_index: usize) -> Result<(), std::io::Error>;

    /// Mark the provided slot as unbootable. The bootloader shall not attempt to
    /// boot from this slot. It can be made bootable again by calling the set_active_slot method.
    fn set_slot_as_unbootable(&mut self, slot_index: usize) -> Result<(), std::io::Error>;

    /// Is the slot bootable?
    fn is_bootable(&self, slot_index: usize) -> Result<bool, std::io::Error>;

    /// Return the suffix used in the partition names. This suffix is used to identify
    /// partition names from the fstab.
    /// The default implementation maps index(0) to 'a'   and index(1) to 'b'
    fn partition_suffix(&self, slot_index: usize) -> Result<&'static str, std::io::Error> {
        match slot_index {
            0 => Ok("a"),
            1 => Ok("b"),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Slot index out of bounds",
            )),
        }
    }

    /// Is the slot marked as successfully booted
    fn is_slot_successful(&self, slot_index: usize) -> Result<bool, std::io::Error>;

    /// Get the slot index for the active slot
    fn active_slot(&self) -> Result<usize, std::io::Error>;
    
}

/// Get the slot suffix from the command line. The kernel command line
    /// must contain the parameter of the form sabaton.boot.slot_suffix=<suffix>
    /// for example sabaton.boot.slot_suffix=a
    pub fn get_slot_suffix_from_cmd_line(command_line: &str) -> Result<&str, std::io::Error> {
        if let Some(slot_command) = command_line.split(' ').find(|e| e.contains("sabaton.boot.slot_suffix=").into()) {
            Ok(slot_command.split('=').last().unwrap().trim())
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Slot suffix not found"))
        }
    }


// A dummy implementation
pub mod mock {
    use std::io::Error;

    use super::{BootControl, get_slot_suffix_from_cmd_line};
    pub struct DefaultImpl;

    impl BootControl for DefaultImpl {
        fn current_slot(&self) -> Result<usize, std::io::Error> {
            let command_line = std::fs::read_to_string("/proc/cmdline")?;
            match get_slot_suffix_from_cmd_line(&command_line)? {
                "a" => Ok(0),
                "b" => Ok(1),
                s => Err(Error::new(std::io::ErrorKind::InvalidData, format!("Invalid slot suffix : {}",s)))
            }
        }

        fn number_of_slots(&self) -> Result<usize, std::io::Error> {
            Ok(2)
        }

        fn set_boot_successful(&mut self) -> Result<(), std::io::Error> {
            Ok(())
        }

        fn set_active_slot(&mut self, _slot_index: usize) -> Result<(), std::io::Error> {
            Ok(())
        }

        fn set_slot_as_unbootable(&mut self, _slot_index: usize) -> Result<(), std::io::Error> {
            Ok(())
        }

        fn is_bootable(&self, _slot_index: usize) -> Result<bool, std::io::Error> {
            Ok(true)
        }

        fn is_slot_successful(&self, _slot_index: usize) -> Result<bool, std::io::Error> {
            Ok(true)
        }

        fn active_slot(&self) -> Result<usize, std::io::Error> {
            Ok(0)
        }
    }
}

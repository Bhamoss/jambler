// make `std` available when testing
#![cfg_attr(not(test), no_std)]
// TODO delete on release
#![allow(unused_variables)]
#![allow(dead_code)]

// TODO get a generic writing/logging macro to replace the RTT with, but later link it with in NRF crate
// TODO only boxes in deduce connection parameters need to be replaced with their own heapless pool boxes, then you should be able to test using std, yet using the lib is still no_std
// TODO also split the deduciton into couple file in directory



// TODO test the assembly on the raspberry pi4
// TODO it has ARMV8 while nrf52 has ARMv7-M, but normally you can write assembly that would work for both -> program remote with vscode on rpi?


pub mod jambler;
pub mod ble_algorithms;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        //assert_eq!(2 + 2, 4);
    }
}

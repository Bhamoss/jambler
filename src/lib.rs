// make `std` available when testing
#![cfg_attr(not(test), no_std)]
// TODO delete on release
#![allow(unused_variables)]
#![allow(dead_code)]

#![feature(asm)]

// TODO get a generic writing/logging macro to replace the RTT with, but later link it with in NRF crate
// TODO only boxes in deduce connection parameters need to be replaced with their own heapless pool boxes, then you should be able to test using std, yet using the lib is still no_std
// TODO also split the deduciton into couple file in directory



// TODO test the assembly on the raspberry pi4
// TODO it has ARMV8 while nrf52 has ARMv7-M, but normally you can write assembly that would work for both -> program remote with vscode on rpi?
/*
For a Raspberry Pi 4 (and also for most other recent Raspberry Pi boards), we can use the armv7-unknown-linux-gnueabihf target.
-> same as nrf
Yet does not contain ASM instructions UDIV (check RBIT and REV16)

nrf:
"thumbv7em-none-eabihf"
eabi: no runtime libc dep
hf: floating point hardware
none: no OS
thumbv7: arm instruction set
m : cortex-m instruction set extension

Thumb: ARM but with an extension that allows mixing in 16-bit instructions
The A64 and A32 instruction sets have fixed instruction lengths of 32-bits.
The T32 instruction set was introduced as a supplementary set of 16-bit instructions that supported improved code density for user code. Over time, T32 evolved into a 16-bit and 32-bit mixed-length instruction set. As a result, the compiler can balance performance and code size trade-off in a single instruction set.

rpi4:
armv7-unknown-linux-gnueabihf

travis-ci: armV8
aarch64-unknown-linux-gnu

They all seem to support RBIT, REV16 and UDIV
*/

pub mod jambler;
pub mod ble_algorithms;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        //assert_eq!(2 + 2, 4);
    }
}

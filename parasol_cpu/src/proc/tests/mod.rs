use ctor::ctor;

mod add;
mod and;
mod bitshift;
mod branch;
mod call_abi;
mod casting;
mod cmux;
mod comparisons;
mod dbg;
mod faults;
mod load_store;
mod mov;
mod mul;
mod neg;
mod not;
mod or;
mod sub;
mod xor;

#[ctor]
unsafe fn init_logging() {
    env_logger::init();
}
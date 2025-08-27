use sunscreen_gpu_runtime::{get_runtimes, init_runtimes};

fn main() {
    // Remove this hack.
    init_runtimes(|_| include_bytes!("./sunscreen_gpu_runtime.release.fatbin"));

    let runtimes = get_runtimes();

    println!("{} runtimes found.", runtimes.len());

    for r in runtimes.iter() {
        let num_devices = r.num_devices().unwrap();
        println!("{num_devices} devices found.");

        for d in 0..r.num_devices().unwrap() {
            println!("{}", r.get_device_name(d.into()).unwrap());
            println!("{:#?}", r.get_device_attributes(d.into()));
        }
    }
}

use anyhow::Result;
use rusb::UsbContext;

fn main() -> Result<()> {
    let ctx = rusb::Context::new()?;
    let count = ctx.devices()?.iter().count();
    println!("libusb ok, {} device(s) visible", count);
    Ok(())
}

//! Export freshly planted synthetic fixtures, never scanner finding values.
#[path = "../tests/support/mod.rs"]
mod support;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (input, manifest) = support::corpus();
    std::fs::create_dir_all("target/scanner-fixtures")?;
    std::fs::write("target/scanner-fixtures/planted.txt", input.as_slice())?;
    std::fs::write(
        "target/scanner-fixtures/benign.txt",
        support::BENIGN.join(""),
    )?;
    let mut description = String::from("family\trule\tstart\tend\n");
    for plant in manifest {
        use std::fmt::Write;
        writeln!(
            description,
            "{}\t{}\t{}\t{}",
            plant.family, plant.rule, plant.range.start, plant.range.end
        )?;
    }
    std::fs::write("target/scanner-fixtures/manifest.tsv", description)?;
    Ok(())
}

use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn repl_reads_commands_until_exit() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ot-commissioner-rs"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"state\nexit\n")
        .unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("disabled"), "{stdout}");
    assert!(stdout.matches("[done]").count() >= 2, "{stdout}");
}

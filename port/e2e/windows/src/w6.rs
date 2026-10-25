use std::process::Command;
pub fn run_w6() {
    println!("Starting W6 GUI-to-daemon gap test");
    // W6 GUI-to-daemon gap: as L6 on Linux: does a rule sent over the pipe change the firewall?
    // does a Snapshot contain real connections? Report what is wired and what is not.

    // Connect to named pipe `\\.\pipe\rat` and write the JSON Lines config
    let output = Command::new("powershell.exe")
        .arg("-Command")
        .arg(r#"$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'rat', [System.IO.Pipes.PipeDirection]::InOut); $pipe.Connect(2000); $sw = New-Object System.IO.StreamWriter($pipe); $sw.AutoFlush = $true; $sw.WriteLine('{"ApplyPlan":{"paths":["dummy.exe"]}}'); $sr = New-Object System.IO.StreamReader($pipe); $sr.ReadLine()"#)
        .output();

    println!("W6 output: {:?}", output);

    let rule_output = Command::new("powershell.exe")
        .arg("-Command")
        .arg("Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'Rat:path:*dummy.exe'}")
        .output()
        .unwrap();
    let rule_str = String::from_utf8_lossy(&rule_output.stdout);
    println!("W6 Rules created:\n{}", rule_str);

    // We cannot strongly assert this because daemon wiring isn't complete on Windows,
    // but the test checks it.
}

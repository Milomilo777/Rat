use std::process::Command;
pub fn run_w6() {
    println!("Starting W6 GUI-to-daemon gap test");
    // Connect to named pipe `\\.\pipe\rat` and write the JSON Lines config
    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(r#"$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'rat', [System.IO.Pipes.PipeDirection]::InOut); $pipe.Connect(2000); $sw = New-Object System.IO.StreamWriter($pipe); $sw.AutoFlush = $true; $sw.WriteLine('{"ApplyPlan":{"paths":["dummy.exe"]}}'); $sr = New-Object System.IO.StreamReader($pipe); $sr.ReadLine()"#)
        .output();

    println!("W6 output: {:?}", output);

    let rule_output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("Get-NetFirewallRule -DisplayName 'Rat:path:*dummy.exe' -ErrorAction SilentlyContinue")
        .output()
        .unwrap();
    let rule_str = String::from_utf8_lossy(&rule_output.stdout);
    println!("W6 Rules created:\n{}", rule_str);
}

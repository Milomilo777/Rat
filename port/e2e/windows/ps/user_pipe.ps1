param([string]$Out)
# Runs as the NON-admin test user. Writes one KEY=value per line.
$lines = New-Object System.Collections.ArrayList
function Note($s) { [void]$lines.Add($s) }
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Note ('WHOAMI=' + $id.Name)
$sids = @($id.Groups | ForEach-Object { $_.Value })
Note ('HAS_INTERACTIVE_SID=' + ($sids -contains 'S-1-5-4'))
Note ('HAS_ADMIN_SID=' + ($sids -contains 'S-1-5-32-544'))

# 1. Try to create a SECOND instance of the pipe.
try {
  $s = New-Object System.IO.Pipes.NamedPipeServerStream('rat', [System.IO.Pipes.PipeDirection]::InOut, 4)
  Note 'CREATE2=SUCCEEDED'
  $s.Dispose()
} catch {
  $e = $_.Exception
  if ($e.InnerException) { $e = $e.InnerException }
  Note ('CREATE2=FAILED:' + $e.GetType().Name + ':' + $e.Message)
}

# 2. Connect as a client and send a valid Hello.
try {
  $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'rat', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
  $c.Connect(4000)
  Note 'CONNECT=OK'
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes('{"Hello":{"protocol_version":1}}' + "`n")
    $c.Write($bytes, 0, $bytes.Length)
    $c.Flush()
    $buf = New-Object byte[] 4096
    $t = $c.ReadAsync($buf, 0, 4096)
    if ($t.Wait(4000)) {
      $n = $t.Result
      if ($n -eq 0) { Note 'HELLO_REPLY=EOF(connection closed by daemon)' }
      else { Note ('HELLO_REPLY=' + [System.Text.Encoding]::UTF8.GetString($buf, 0, $n).Trim()) }
    } else {
      Note 'HELLO_REPLY=NONE(timeout, connection kept silent)'
    }
  } catch {
    $e = $_.Exception
    if ($e.InnerException) { $e = $e.InnerException }
    Note ('HELLO_REPLY=IOERROR:' + $e.GetType().Name + ':' + $e.Message)
  }
  $c.Dispose()
} catch {
  $e = $_.Exception
  if ($e.InnerException) { $e = $e.InnerException }
  Note ('CONNECT=FAILED:' + $e.GetType().Name + ':' + $e.Message)
}
Note 'END'
Set-Content -LiteralPath $Out -Value $lines -Encoding ASCII

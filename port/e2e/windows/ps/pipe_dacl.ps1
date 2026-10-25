$ErrorActionPreference = 'Continue'
# Method 1: connect as a client with read+write and read the pipe's DACL.
try {
  $p = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'rat', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
  $p.Connect(5000)
  $sec = $p.GetAccessControl()
  Write-Output ('SDDL1=' + $sec.GetSecurityDescriptorSddlForm('Access'))
  $p.Dispose()
} catch {
  $e = $_.Exception
  if ($e.InnerException) { $e = $e.InnerException }
  Write-Output ('ERR1=' + $e.GetType().Name + ': ' + $e.Message)
}
# Method 2: Get-Acl on the pipe path.
try {
  $a = Get-Acl -LiteralPath '\\.\pipe\rat'
  Write-Output ('SDDL2=' + $a.GetSecurityDescriptorSddlForm('Access'))
} catch {
  Write-Output ('ERR2=' + $_.Exception.Message)
}
Write-Output 'END'

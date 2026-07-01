# If execution policy blocks this script, use build-ghidra-12.1.2.bat instead.
$ErrorActionPreference = "Stop"

$env:GHIDRA_INSTALL_DIR = "C:\Users\ptthe\Desktop\ghidra_12.1.2_PUBLIC"
Set-Location $PSScriptRoot

.\gradlew.bat build @args

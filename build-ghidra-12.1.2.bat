@echo off
setlocal

set "GHIDRA_INSTALL_DIR=C:\Users\ptthe\Desktop\ghidra_12.1.2_PUBLIC"
cd /d "%~dp0"

if /I "%~1"=="test" (
    shift
    call gradlew.bat test %*
) else if /I "%~1"=="assemble" (
    shift
    call gradlew.bat assemble %*
) else (
    rem Default: full build (compile, package extension zip, run tests)
    call gradlew.bat build %*
)

endlocal
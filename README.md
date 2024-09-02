# stealer
### Overview

The task involved reverse engineering a `.Net 32-bit` executable named `snake.mal`. The primary objective was to analyze the executable, identify its functionality, and decode any hidden or encrypted data within the file. The reversing process was conducted using several tools, including `de4dot` for deobfuscation and custom scripts to decrypt strings used by the malware.

### Initial Analysis

Upon opening `snake.mal.exe` in a decompiler, it was evident that the executable was heavily obfuscated. The functions and classes were renamed to nonsensical names, making manual analysis difficult.

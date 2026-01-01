rule Shellcode_Common {
    meta:
        description = "Detects common shellcode patterns"
        author = "SandSight"
    strings:
        // Common NOP sleds
        $nop1 = { 90 90 90 90 90 90 90 90 }
        
        // Stack pivoting (x86/x64)
        $pivot1 = { 94 C3 } // xchg eax, esp; ret
        $pivot2 = { 87 E0 C3 } // xchg esp, eax; ret
        
        // Common payload prefixes
        $sh1 = { 31 C0 50 68 2F 2F 73 68 } // xor eax, eax; push eax; push "//sh"
        $sh2 = { 68 2F 62 69 6E } // push "/bin"
        
    condition:
        any of them
}

rule Suspicious_Memory_Regions {
    meta:
        description = "Detects suspicious patterns in memory dumps"
    strings:
        $mimikatz = "mimikatz" nocase
        $meterpreter = "meterpreter" nocase
        $wce = "wce" nocase
    condition:
        any of them
}

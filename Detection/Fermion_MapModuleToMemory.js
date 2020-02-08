//---------------------------------------------------//
// Detect NtWriteVirtualMemory writing a PE header & //
// detect if subsequently NtCreateThreadEx calls the //
// PE EntryPoint.                                    //
//---------------------------------------------------//

// pFunction
var pNtWriteVirtualMemory = Module.findExportByName('ntdll.dll', 'NtWriteVirtualMemory');
var pNtCreateThreadEx = Module.findExportByName('ntdll.dll', 'NtCreateThreadEx');

// Globals
var epArray = new Array();

// Hooks
Interceptor.attach(pNtWriteVirtualMemory, {
    onEnter: function (args) {
        // Check the first 2 bytes 
        var isMZ = args[2].readU16();
        if (isMZ == 0x5A4D) { // MZ
            // Write large enough for e_lfanew
            if (args[3].toInt32() > 0x40) {
                var e_lfanew = (args[2].add(0x3c)).readU32();
                // Write large enough for PE\0\0
                if (args[3].toInt32() > (e_lfanew + 4)) {
                    var peHeader = args[2].add(e_lfanew);
                    var isPE = peHeader.readU32();
                    if (isPE == 0x4550) {
                        send("[!] WARNING DETECTED: NtWriteVirtualMemory -> PE");
                        var optHeader = peHeader.add(0x18);
                        if (optHeader.readU16() == 0x020b) {
                            send("    |-> PE is x64..");
                        } else {
                            send("    |-> PE is x86..");
                        }
                        var addressOfEntryPoint = optHeader.add(0x10);
                        var entryPointOffet = args[1].add(addressOfEntryPoint.readU32());

                        // Add entrypoint to an array, we can use
                        // this to later monitor thread creation
                        epArray.push(entryPointOffet.toString());
                        send("    |-> lpEntryPoint: " + entryPointOffet);
                        send("    |-> Hexdump: \n" + hexdump(args[2], {length:100}));
                    }
                }
            }
        }
    }
});

Interceptor.attach(pNtCreateThreadEx, {
    onEnter: function (args) {
        if (epArray.indexOf(args[4].toString()) != -1) {
            send("\n[!] WARNING DETECTED: NtWriteVirtualMemory -> PE -> NtCreateThreadEx");
            send("    |-> lpStartAddress: " + args[4]);
        }
    }
});
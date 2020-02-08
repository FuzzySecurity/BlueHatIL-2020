rule SharpSploit_ModuleLoadFromDisk
{
    meta:
        author = "Ruben Boonen (@FuzzySec)"
        description = "Detect SharpSploit module load from disk."

    strings:
        $s1 = "ModuleNativePath=" ascii wide nocase
        $s2 = /\\\\(S|s)harp(S|s)ploit\.dll;\\r\\n/

    condition:
        all of ($s*)
}

rule SharpSploit_DynamicInvoke_ManualMapModule
{
    meta:
        author = "Ruben Boonen (@FuzzySec)"
        description = "Detect SharpSploit function calls used to manually map a module to memory."

    strings:
        $s1 = "MapModuleToMemory" ascii wide nocase
        $s2 = "GetLibraryAddress" ascii wide nocase
        $s3 = "GetLoadedModuleAddress" ascii wide nocase
        $s4 = "GetExportAddress" ascii wide nocase
        $s5 = "GetPeMetaData" ascii wide nocase
        $s6 = "RelocateModule" ascii wide nocase
        $s7 = "RewriteModuleIAT" ascii wide nocase
        $s8 = "GetNativeExportAddress" ascii wide nocase
        $s9 = "SetModuleSectionPermissions" ascii wide nocase
        $s10 = "CallMappedPEModule" ascii wide nocase

        $t1 = /MethodNamespace=[\w\.]+DynamicInvoke\.Generic/

    condition:
        $t1 and any of ($s*)
}

rule SharpSploit_DynamicInvoke_NativeFunctionCall
{
    meta:
        author = "Ruben Boonen (@FuzzySec)"
        description = "Detect SharpSploit use of native function calls."

    strings:
        $s1 = "NtQueryInformationProcess" ascii wide nocase
        $s2 = "NtAllocateVirtualMemory" ascii wide nocase
        $s3 = "NtWriteVirtualMemory" ascii wide nocase
        $s4 = "LdrGetProcedureAddress" ascii wide nocase
        $s5 = "LdrLoadDll" ascii wide nocase
        $s6 = "NtProtectVirtualMemory" ascii wide nocase
        $s7 = "NtCreateThreadEx" ascii wide nocase

        $t1 = /MethodNamespace=[\w\.]+DynamicInvoke\.Native/

    condition:
        $t1 and any of ($s*)
}

rule SharpSploit_Suspicious_ILMethodSignature
{
    meta:
        author = "Ruben Boonen (@FuzzySec)"
        description = "Detect SharpSploit use of suspicious IL method signatures."

    strings:
        $s1_NtQueryInformationProcess = /unsigned int32\s+\(int,value class PROCESSINFOCLASS,int,int32,unsigned int32&\);/
        $s2_LdrLoadDll = /unsigned int32\s+\(int,unsigned int32,value class UNICODE_STRING&,int&\);/
        $s3_NtCreateThreadEx = /value class NTSTATUS\s+\(int&,value class ACCESS_MASK,int,int,int,int,bool,int32,int32,int32,int\);/

    condition:
        any of ($s*)
}

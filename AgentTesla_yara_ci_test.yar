import"pe"
import"dotnet"
//import"hash"

rule AgentTesla
{
    meta:
        hash1 = "008cd26a66301f3d1eff70394c17a33a"
        //hash2 = "BA0B49885B63ABDF7B50B90A701BDC35"
        //hash3 = "161D29B294DC41B48FBB06153A102FE3"
        //hash4 = "6CCA77EC5EAA84731CF3F4F9F6BCA1C4"
        //hash5 = "123457EC5EAA84731CF3F4F9F6BCA1C4"
    strings:
        $sample_1_string_1 = "finalCIT"
        $sample_1_string_2 = "DownloadData"
        $sample_1_string_3 = "repub"
        $sample_1_string_4 = "load"
        $sample_1_string_5 = "username"
        //$sample_1_string_6 = "username"

        $sample_2_string_1 = "Silent Miner"
        $sample_2_string_2 = "V2.exe"
        $sample_2_string_3 = "WebRequest"
        $sample_2_string_4 = "WebResponse"
        //$sample_2_string_5 = "username"


        $sample_3_string_1 = "Mono.Remoting"
        $sample_3_string_2 = "Kill"
        $sample_3_string_3 = "Remoting.Contexts"
        $sample_3_string_4 = "Threading.ExecutionContext"
        //$sample_3_string_5 = "username"


        $sample_4_string_1 = "label10"
        $sample_4_string_2 = "PowerOn1"
        $sample_4_string_3 = "executed" fullword wide
        $sample_4_string_4 = "Monitor Control" fullword wide
        //$sample_4_string_5 = "username"
    condition:
        pe.is_pe
        and
        dotnet.is_dotnet
        and
        (pe.number_of_sections == 3 or pe.number_of_sections == 4 or pe.number_of_sections == 5)
        and 
        (pe.linker_version.major == 0x30 or pe.linker_version.major == 0x50 or pe.linker_version.major == 0x06 or pe.linker_version.major == 0x08)
        and
        (pe.subsystem == 0x02 or pe.subsystem == 0x03)
        and
        (pe.dll_characteristics == 0x8540 or pe.dll_characteristics == 0x8560)
        and
        dotnet.number_of_streams == 5
        and
        dotnet.version == "v4.0.30319"
        and
        (
            (
                $sample_1_string_1 and $sample_1_string_2 and $sample_1_string_3 and $sample_1_string_4 and $sample_1_string_5 in (dotnet.streams[1].offset..dotnet.streams[2].offset)
                and
                pe.version_info["InternalName"] contains "finalCIT.exe"
            )
            or
            (
                $sample_2_string_1 and $sample_2_string_2 and $sample_2_string_3 and $sample_2_string_4 in (dotnet.streams[1].offset..dotnet.streams[2].offset)
                and
                pe.version_info["InternalName"] contains "Silent Miner V2.exe"
            )
            or
            (
                $sample_3_string_1 and $sample_3_string_2 and $sample_3_string_3 and $sample_3_string_4 in (dotnet.streams[1].offset..dotnet.streams[2].offset)
                and
                pe.version_info["InternalName"] contains "VTgsFnd.exe"
            )
            or
            (
                $sample_4_string_1 and $sample_4_string_2 in (dotnet.streams[1].offset..dotnet.streams[2].offset)
                and
                $sample_4_string_3 and $sample_4_string_4 in (dotnet.streams[2].offset..dotnet.streams[2].offset + 0x4ff)
                and
                pe.version_info["InternalName"] contains "BuiltInPermissionF.exe"
            )
        )
}

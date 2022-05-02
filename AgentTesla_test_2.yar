import"pe"
import"dotnet"
//import"hash"

rule AgentTesla
{
    meta:
        hash1 = "1502a41b01323c4b5c74dda0db40a7e0"
        hash2 = "3711ddebeb8c221c5cb200b6363316d4"
        hash3 = "4320d0fbe360176198f764348cf506bb"
        hash4 = "32aa8718b727175460d1b90a6b3e5acc"
        hash5 = "cab3f3c0f8ba1b811469c44e81bc714d"
        hash6 = "74d4050aca3ca75404e7435a06e9b1d9"
        hash7 = "f1f9ff435b9c36fe509dde17a801e83b"
        hash8 = "d81d919f7bd602d632ad036d084b65bf"
        hash9 = "4e1404654f894865670b5db1a32cd95f"
        hash10 = "03c7d9e6ef1b789c59bfbc01b7f3e161"
        hash11 = "23a71e1e392197ef0764524510ea3363"
        hash12 = "8df9142a30940f953fe7ffe91f65d5f3"
        hash13 = "5ccef6c46f3adcdd85baea27f7ff1e22"
        hash14 = "2e0317d2a91036f4d7573acdd4f5e1b2"
        hash15 = "ef3444b8d07501e983b0f93df2eee6e7"
        hash16 = "b0c1d4c008da7ec1093b4ad59922bf27"
        hash17 = "84a36e30d47206fe4ee4855a5d14942d"
        hash18 = "7bf4f98f6edef5efe9b9a10bfe6c10f5"
        hash19 = "ec5044ee5f8bf864274fd36feef8b287"
        hash20 = "971f79e491ff0440d0e8eba4e85775ea"
        
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

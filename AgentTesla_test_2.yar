import"pe"
import"dotnet"
//import"hash"

rule AgentTesla
{
    meta:
        hash = "1502a41b01323c4b5c74dda0db40a7e0, 3711ddebeb8c221c5cb200b6363316d4, 4320d0fbe360176198f764348cf506bb, 32aa8718b727175460d1b90a6b3e5acc, cab3f3c0f8ba1b811469c44e81bc714d, 74d4050aca3ca75404e7435a06e9b1d9, f1f9ff435b9c36fe509dde17a801e83b, d81d919f7bd602d632ad036d084b65bf, 4e1404654f894865670b5db1a32cd95f, 03c7d9e6ef1b789c59bfbc01b7f3e161, 23a71e1e392197ef0764524510ea3363, 8df9142a30940f953fe7ffe91f65d5f3, 5ccef6c46f3adcdd85baea27f7ff1e22, 2e0317d2a91036f4d7573acdd4f5e1b2, ef3444b8d07501e983b0f93df2eee6e7, b0c1d4c008da7ec1093b4ad59922bf27, 84a36e30d47206fe4ee4855a5d14942d, 7bf4f98f6edef5efe9b9a10bfe6c10f5, ec5044ee5f8bf864274fd36feef8b287, 971f79e491ff0440d0e8eba4e85775ea, ad06e9208811dc1138397ac1030c3872, 13382d0c3781cd481ddc1f371f491df4, 7ffec2d3d819d3ad38528e21e2b9ae3e"

    strings:
        $blob_string1 = "$042e361e-8146-471e-a822-671ed72e6526"
        $blob_string2 = "$eff3c0e3-c71a-41b1-a883-09e041a82806"
        $blob_string3 = "$edfffca9-3b97-43b7-a50a-b29c7520e8b6"
        $blob_string4 = "$c27b1d8c-e849-4b6f-a020-c5260f83b43e"
        $blob_string5 = "$e5e8e233-23e0-4b57-8ae3-d98230e2fa65"
        $blob_string6 = "$86da06e9-7b13-4eb6-844d-368d971b99b6"  
        $blob_string7 = "$85b12263-681a-43f8-b0d6-4f79cd75abd5"  
        $blob_string8 = "xb123"  
        $blob_string9 = "xb123"  

        $string1 = "WrapNonExceptionThrows"

        //$sample_1_string_1 = "finalCIT"
        //$sample_1_string_2 = "DownloadData"
        //$sample_1_string_3 = "repub"
        //$sample_1_string_4 = "load"
        //$sample_1_string_5 = "username"
        //$sample_1_string_6 = "username"

        //$sample_2_string_1 = "Silent Miner"
        //$sample_2_string_2 = "V2.exe"
        //$sample_2_string_3 = "WebRequest"
        //$sample_2_string_4 = "WebResponse"
        //$sample_2_string_5 = "username"


        //$sample_3_string_1 = "Mono.Remoting"
        //$sample_3_string_2 = "Kill"
        //$sample_3_string_3 = "Remoting.Contexts"
        //$sample_3_string_4 = "Threading.ExecutionContext"
        //$sample_3_string_5 = "username"


        //$sample_4_string_1 = "label10"
        //$sample_4_string_2 = "PowerOn1"
        //$sample_4_string_3 = "executed" fullword wide
        //$sample_4_string_4 = "Monitor Control" fullword wide
        //$sample_4_string_5 = "username"
    condition:
        filesize > 10KB and filesize < 2000KB
        and
        pe.is_pe
        and
        dotnet.is_dotnet
        and
        pe.number_of_sections == 3
        and 
        (pe.linker_version.major == 0x30 or pe.linker_version.major == 0x06)
        and
        pe.subsystem == 0x02
        and
        pe.dll_characteristics == 0x8540
        and
        dotnet.number_of_streams == 5
        and
        dotnet.version == "v4.0.30319"
        and
        (
            any of ($blob_string*) in (dotnet.streams[3].offset..dotnet.streams[3].offset + 0x4ff)
            or
            any of ($blob_string*) in (dotnet.streams[4].offset..dotnet.streams[4].offset + 0x4ff)
        )
        and
        (
            $string1 in (dotnet.streams[3].offset..dotnet.streams[3].offset + 0x4ff)
            or
            $string1 in (dotnet.streams[4].offset..dotnet.streams[4].offset + 0x4ff)
        ) 
}

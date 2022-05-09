import"pe"
import"dotnet"
//import"hash"

rule AgentTesla
{
    meta:
        hash = "1502a41b01323c4b5c74dda0db40a7e0"

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

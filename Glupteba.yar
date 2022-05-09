import"pe"

rule Trojan_Glupteba
{
    meta:
        hash = "d98e33b66343e7c96158444127a117f6"

    strings:
        $string1 = "Global\\qtxp9g8w" fullword wide
        $string2 = "get process ID by name"
        $string3 = "failed to inject DLL"
    condition:
        filesize > 10KB and filesize < 2000KB
        and
        pe.is_pe
        and
        pe.number_of_sections > 3
        and 
        pe.sections[1].name == ".rdata"
        and
        all of ($string*) in (pe.rva_to_offset(pe.sections[1].virtual_address)..pe.rva_to_offset(pe.sections[2].virtual_address))
}

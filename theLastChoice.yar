import "hash"
rule locky_detect {
    meta:
        author = "theLastChoice Killer"
        description = "Detects theLastChoice malware "
        date = "2024-12-2"
        version = "1.0"
    strings:
        $theLastChoice_1 =  "GetSidSubAuthority"
        $theLastChoice_2 =  "ShellExecute"
        $theLastChoice_3 = "AdjustTokenPrivileges"
        $theLastChoice_4 = "cdnverify.net"

    condition:
        filesize > 0 and  (hash.sha256(0, filesize) == "54D2ED7801D2ABDC0127EFF52DBB76C3763DCAC6B16AB92E82BBE86EB70BC9B0" or 
        any of ($theLastChoice_*))
}


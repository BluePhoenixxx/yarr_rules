import "hash"
rule locky_detect {
    meta:
        author = "theFirstChoice Killer"
        description = "Detects theFirstChoice malware "
        date = "2024-12-2"
        version = "1.0"
    strings:
        $theFirstChoice_1 = "D21CQAT01-N.NHOM21.everybodysayyeah.run.place"
        $theFirstChoice_2 = "GetKernelObjectSecurity "
        $theFirstChoice_3 = "CreateThreadpoolTimer"

    condition:
        filesize > 0 and  (hash.sha256(0, filesize) == "971D131D2C5A1F41890A8462D4C238455E377F0AF9A73B5BD2F5528F888804CA" or 
        any of ($theFirstChoice_*))
}

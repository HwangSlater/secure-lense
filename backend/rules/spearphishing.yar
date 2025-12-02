rule korean_phishing_keywords {
    meta:
        description = "Detects Korean spear-phishing keywords"
    strings:
        $k1 = "긴급" wide ascii
        $k2 = "계좌" wide ascii
        $k3 = "비밀번호 변경" wide ascii
        $k4 = "당첨" wide ascii
        $k5 = "세금 환급" wide ascii
        $k6 = "본인 인증" wide ascii
    condition:
        2 of them
}

rule double_extension_attachment {
    meta:
        description = "Detects suspicious double extensions"
    strings:
        $pdf_exe = ".pdf.exe" nocase
        $doc_exe = ".docx.exe" nocase
        $zip_exe = ".zip.exe" nocase
    condition:
        any of them
}

rule spoofed_email_headers {
    meta:
        description = "Detects email header spoofing indicators"
    strings:
        $h1 = "Reply-To:" nocase
        $h2 = "Return-Path:" nocase
        $h3 = "From:" nocase
    condition:
        all of them
}


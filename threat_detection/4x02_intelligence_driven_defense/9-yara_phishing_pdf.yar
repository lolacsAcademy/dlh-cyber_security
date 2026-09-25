rule HEALTHBANE_Phishing_PDF
{
    meta:
        author = "student"
        description = "Detects HEALTHBANE phishing PDFs using campaign tooling and credential-harvesting URL patterns"
        date = "2026-09-25"
        reference = "HEALTHBANE"
        threat_level = "high"
        confidence = "high"

    strings:
        // PDF file signature.
        $pdf_magic = "%PDF" ascii

        // Tooling observed in both HEALTHBANE phishing PDF samples.
        $tool = "wkhtmltopdf 0.12.6" ascii nocase

        // Credential-harvesting paths.
        $path_verify = "/verify" ascii nocase
        $path_login = "/login" ascii nocase
        $path_portal = "/portal" ascii nocase
        $path_enroll = "/enroll" ascii nocase

        // URL parameters used by the campaign.
        $param_token = "token=" ascii nocase
        $param_id = "id=" ascii nocase

        // Campaign-related domain fragments.
        $domain_meddefense = "meddefense-portal.com" ascii nocase
        $domain_medequip = "medequip-supplies.net" ascii nocase

    condition:
        // Require a PDF, HEALTHBANE tooling, and at least two
        // credential-harvesting URL indicators.
        $pdf_magic at 0 and
        $tool and
        2 of ($path_*, $param_*, $domain_*)

/*
Test results:
- phishing_sample.pdf: TRUE POSITIVE
- healthbane_lure_02.pdf: TRUE POSITIVE
- clean_invoice.pdf: TRUE NEGATIVE
- benign_invoice.pdf: TRUE NEGATIVE
*/
}

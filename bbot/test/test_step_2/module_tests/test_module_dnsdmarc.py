from .base import ModuleTestBase

raw_dmarc_txt = '"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc.rua@reports.blacklanternsecurity.notreal; ruf=mailto:dmarc.ruf@reports.blacklanternsecurity.notreal, mailto:d@vali.email"'
raw_dmarc_txt_none = (
    '"v=DMARC1; p=none; pct=100; rua=mailto:dmarc.rua@reports.blacklanternsecurity.notreal; ruf=mailto:d@vali.email"'
)
raw_dmarc_txt_quarantine = '"v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc.rua@reports.blacklanternsecurity.notreal; ruf=mailto:d@vali.email"'
raw_dmarc_txt_norua = '"v=DMARC1; p=reject; pct=100; fo=0:1:d:s; adkim=s; aspf=s;"'
raw_dmarc_txt_typeo = (
    '"v=DMARC1; p=reject pct=100; rua=mailto:dmarc.rua@reports.blacklanternsecurity.notreal; ruf=mailto:d@vali.email"'
)
raw_dmarc_txt_pctnot100 = (
    '"v=DMARC1; p=reject; pct=50; rua=mailto:dmarc.rua@reports.blacklanternsecurity.notreal; ruf=mailto:d@vali.email"'
)
raw_dmarc_txt_sp_none = '"v=DMARC1; p=reject; sp=none; pct=100; rua=mailto:dmarc.rua@reports.blacklanternsecurity.notreal; ruf=mailto:d@vali.email;"'
raw_dmarc_txt_sp_quarantine = '"v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc.rua@reports.blacklanternsecurity.notreal; ruf=mailto:d@vali.email;"'

raw_dmarc_txt_rfc_invalid = '"v=DMARC2; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc.rua@reports.blacklanternsecurity.notreal; ruf=mailto:d@vali.email;"'

raw_txt_wildcard_spf = "v=spf1 -all"


class TestDNSDMARC(ModuleTestBase):
    targets = [
        "blacklanternsecurity.notreal",
        "a.notreal",
        "b.notreal",
        "c.notreal",
        "d.notreal",
        "e.notreal",
        "f.notreal",
        "g.notreal",
        "h.notreal",
        "i.notreal",
    ]
    modules_overrides = ["dnsdmarc", "speculate"]
    config_overrides = {
        "modules": {"dnsdmarc": {"emit_raw_dns_records": True, "emit_vulnerabilities": True}},
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.notreal": {
                    "A": ["127.0.0.11"],
                },
                "_dmarc.blacklanternsecurity.notreal": {
                    "A": ["127.0.0.22"],
                    "TXT": [raw_dmarc_txt],
                },
                "_dmarc._dmarc.blacklanternsecurity.notreal": {
                    "TXT": [raw_dmarc_txt],
                },
                "a.notreal": {
                    "A": ["127.0.0.33"],
                },
                "_dmarc.a.notreal": {
                    "TXT": [raw_dmarc_txt_none],
                },
                "b.notreal": {
                    "A": ["127.0.0.44"],
                },
                "_dmarc.b.notreal": {
                    "TXT": [raw_dmarc_txt_quarantine],
                },
                "c.notreal": {
                    "A": ["127.0.0.55"],
                },
                "_dmarc.c.notreal": {
                    "TXT": [raw_dmarc_txt_norua],
                },
                "d.notreal": {
                    "A": ["127.0.0.66"],
                },
                "_dmarc.d.notreal": {
                    "TXT": [raw_dmarc_txt_typeo],
                },
                "e.notreal": {
                    "A": ["127.0.0.77"],
                },
                "_dmarc.e.notreal": {
                    "TXT": [raw_dmarc_txt_pctnot100],
                },
                "f.notreal": {
                    "A": ["127.0.0.88"],
                },
                "_dmarc.f.notreal": {
                    "TXT": [raw_dmarc_txt_sp_none],
                },
                "g.notreal": {
                    "A": ["127.0.0.99"],
                },
                "_dmarc.g.notreal": {
                    "TXT": [raw_dmarc_txt_sp_quarantine],
                },
                "h.notreal": {
                    "A": ["127.0.1.11"],
                },
                "_dmarc.h.notreal": {
                    "TXT": [raw_txt_wildcard_spf, raw_dmarc_txt_norua, raw_dmarc_txt_pctnot100],
                },
                "i.notreal": {
                    "A": ["127.0.1.22"],
                },
            }
        )

    def check(self, module_test, events):
        assert any(
            e.type == "RAW_DNS_RECORD" and e.data["answer"] == raw_dmarc_txt for e in events
        ), "Failed to emit RAW_DNS_RECORD"

        assert any(
            e.type == "EMAIL_ADDRESS" and e.data == "dmarc.rua@reports.blacklanternsecurity.notreal" for e in events
        ), "Failed to detect RUA email address"
        assert any(
            e.type == "EMAIL_ADDRESS" and e.data == "dmarc.ruf@reports.blacklanternsecurity.notreal" for e in events
        ), "Failed to detect RUF email address"
        assert any(
            e.type == "EMAIL_ADDRESS" and e.data == "d@vali.email" for e in events
        ), "Failed to detect RUF email address"

        assert not any(
            e.type == "VULNERABILITY" and e.data["host"] == "_dmarc.blacklanternsecurity.notreal" for e in events
        ), "_dmarc.blacklanternsecurity.notreal incorrectly reported as vulnerable"

        assert any(
            e.type == "VULNERABILITY"
            and e.data["host"] == "_dmarc.a.notreal"
            and e.data["description"]
            == "policy is report-only so no quarantine or rejection will occur, subdomain policy is report-only so no quarantine or rejection will occur"
            for e in events
        )

        assert not any(
            e.type == "VULNERABILITY" and e.data["host"] == "_dmarc.b.notreal" for e in events
        ), "Incorrectly marked _dmarc.b.notreal as vulnerable"
        assert not any(
            e.type == "VULNERABILITY" and e.data["host"] == "_dmarc.c.notreal" for e in events
        ), "Incorrectly marked _dmarc.b.notreal as vulnerable"

        assert any(
            e.type == "VULNERABILITY"
            and e.data["host"] == "_dmarc.d.notreal"
            and e.data["description"]
            == "policy action invalid or not provided (p='reject pct=100'), subdomain policy action invalid (sp='reject pct=100')"
            for e in events
        )
        assert any(
            e.type == "VULNERABILITY"
            and e.data["host"] == "_dmarc.e.notreal"
            and e.data["description"] == "policy does not apply to all email (pct=50)"
            for e in events
        )
        assert any(
            e.type == "VULNERABILITY"
            and e.data["host"] == "_dmarc.f.notreal"
            and e.data["description"] == "subdomain policy is report-only so no quarantine or rejection will occur"
            for e in events
        )

        assert not any(e.type == "VULNERABILITY" and e.data["host"] == "_dmarc.g.notreal" for e in events)

        assert any(
            e.type == "VULNERABILITY"
            and e.data["host"] == "_dmarc.h.notreal"
            and e.data["description"]
            == "multiple DMARC policies have been published with at least one vulnerable policy present"
            for e in events
        )

        assert any(
            e.type == "VULNERABILITY"
            and e.data["host"] == "_dmarc.i.notreal"
            and e.data["description"] == "DMARC policy absent for this domain"
            for e in events
        )


class TestDNSDMARCRecursiveRecursion(TestDNSDMARC):
    config_overrides = {
        "scope": {"report_distance": 1},
        "modules": {"dnsdmarc": {"emit_raw_dns_records": True}},
    }

    def check(self, module_test, events):
        assert not any(
            e.type == "RAW_DNS_RECORD" and e.data["host"] == "_dmarc._dmarc.blacklanternsecurity.notreal"
            for e in events
        ), "Unwanted recursion occurring"

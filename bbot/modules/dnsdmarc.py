# dnsdmarc.py
#
# Checks for and parses common DMARC TXT records, e.g. _dmarc.target.domain
#
# DMARC policies may contain email addresses for reporting destinations, typically these are software processed inboxes, but they may also be to individual humans or team inboxes.
#
# The domain portion of the email address is also passively checked and added as appropriate, for additional inspection by other modules.
#
# Example TXT record: v=DMARC1; p=reject; fo=1; rua=mailto:dmarc-rua@example.com,mailto:someone@third.party; ruf=mailto:dmarc-ruf@example.com,mailto:haseen@someone@third.party;"
#
# TODO: extract %{UNIQUE_ID}% from hosted services as ORG_STUB ?
#   e.g. %{UNIQUE_ID}%@dmarc.hosted.service.provider is usually a tenant specific ID.
#   e.g. dmarc@%{UNIQUE_ID}%.hosted.service.provider is usually a tenant specific ID.

from bbot.modules.base import BaseModule
from bbot.core.helpers.dns.helpers import service_record

import re

from bbot.core.helpers.regexes import email_regex

_dmarc_regex = r"^v=(?P<v>DMARC[0-9\s]+); *(?P<kvps>.*)$"
dmarc_regex = re.compile(_dmarc_regex, re.I)

_dmarc_kvp_regex = r"(?P<k>\w+)=(?P<v>[^;]+);*"
dmarc_kvp_regex = re.compile(_dmarc_kvp_regex)

_csul = r"(?P<uri>[^, ]+)"
csul = re.compile(_csul)


class dnsdmarc(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "RAW_DNS_RECORD", "VULNERABILITY"]
    flags = ["subdomain-enum", "cloud-enum", "email-enum", "passive", "safe"]
    meta = {
        "description": "Check for DMARC records",
        "author": "@colin-stubbs",
        "created_date": "2024-05-26",
    }
    options = {
        "emit_emails": True,
        "emit_raw_dns_records": False,
        "emit_vulnerabilities": False,
    }
    options_desc = {
        "emit_emails": "emit EMAIL_ADDRESS events",
        "emit_raw_dns_records": "Emit RAW_DNS_RECORD events",
        "emit_vulnerabilities": "Emit VULNERABILITY events",
    }

    async def setup(self):
        self.emit_emails = self.config.get("emit_emails", True)
        self.emit_raw_dns_records = self.config.get("emit_raw_dns_records", False)
        self.emit_vulnerabilities = self.config.get("emit_vulnerabilities", False)
        return await super().setup()

    def _incoming_dedup_hash(self, event):
        # dedupe by parent
        parent_domain = self.helpers.parent_domain(event.data)
        return hash(parent_domain), "already processed parent domain"

    async def filter_event(self, event):
        if "_wildcard" in str(event.host).split("."):
            return False, "event is wildcard"

        # there's no value in inspecting service records
        if service_record(event.host) == True:
            return False, "service record detected"

        return True

    async def validateDMARC(self, event, host, answer, tags):
        dmarc = False
        valid = True
        reasons = []

        vulnerable = False
        vulnerabilities = []

        policy = {
            # RFC-7489 - defaults
            "v": "",  # Value must be "DMARC1"
            "p": "",  # none/quarantine/reject - No default, explicit definition required
            "sp": "",  # No default, inherits value from p if sp not explicitly provided
            "pct": "100",  # 100%
            # TODO: actually do checks on the below?
            "adkim": "r",  # r|s == relaxed|strict
            "aspf": "r",  # r|s == relaxed|strict
            "fo": "0",  # 0/1/d/s - forensic reporting options, e.g. "1:d:s", refer to RFC spec
            "rf": "afrf",  # afrf - No other values supported
            "ri": "86400",  # 32-bit unsigned integer, minimum value of 0 and a maximum value of 4,294,967,295 (inclusive)
            "rua": "",  # aggregate reporting destinations, optional, default is nothing
            "ruf": "",  # forensic reporting destinations, optional, default is nothing
        }

        dmarc_match = dmarc_regex.search(answer)

        if dmarc_match and dmarc_match.group("v") and dmarc_match.group("kvps"):
            dmarc = True
            policy["v"] = dmarc_match.group("v")
            kvps = dmarc_kvp_regex.finditer(dmarc_match.group("kvps"))

            for match in kvps:
                key = match.group("k").lower()
                policy[key] = match.group("v")

                if not key in policy.keys():
                    valid = False
                    reasons.append("RFC undefined KVP key '" + key + "' found")

                if key == "rua" or key == "ruf":
                    for csul_match in csul.finditer(policy[key]):
                        if csul_match.group("uri") and csul_match.group("uri") != "":
                            # TODO: validate format of each comma separated URI in RUA/RUF text
                            # e.g. only mailto: based URI's are supported, HTTP/HTTPS etc indicates misconfiguration/vulnerability due to lack of report delivery
                            # e.g. missing mailto: prefix for emails indicates misconfiguraiton/vulnerability due to lack of report delivery
                            for email_match in email_regex.finditer(csul_match.group("uri")):
                                start, end = email_match.span()
                                email = csul_match.group("uri")[start:end]

                                if self.emit_emails:
                                    await self.emit_event(
                                        email,
                                        "EMAIL_ADDRESS",
                                        tags=tags.append(f"dmarc-record-{key}"),
                                        parent=event,
                                    )

            if policy["v"] != "DMARC1":
                valid = False
                reasons.append(
                    "policy version is not RFC compliant, 'v' key has value '"
                    + policy["v"]
                    + "' instead of required 'DMARC1'"
                )

                vulnerable = True
                vulnerabilities.append(
                    "DMARC policy is not RFC compliant and may not be utilised by all third parties"
                )

            if ( policy["p"] == "none" or policy["p"] == "quarantine" or policy["p"] == "reject" ) and policy["rua"] == "" and policy["ruf"] == "":
                vulnerable = True
                vulnerabilities.append("DMARC policy action is valid but reporting destinations were not provided")

            if policy["p"] == "none":
                vulnerable = True
                vulnerabilities.append("DMARC policy is report-only")
            elif policy["p"] == "quarantine" and policy["pct"] != "100":
                vulnerable = True
                vulnerabilities.append(
                    "DMARC policy is quarantine-only with partial enforcement (pct=" + policy["pct"] + ")"
                )
            elif not policy["p"] == "quarantine" and not policy["p"] == "reject":
                vulnerable = True
                vulnerabilities.append("DMARC policy action invalid or not provided (p='" + policy["p"] + "')")

            if policy["sp"] == "":
                # sp inherits value from p if not explicitly provided
                policy["sp"] = policy["p"]

            if policy["sp"] == "none":
                vulnerable = True
                vulnerabilities.append("DMARC subdomain policy is report-only")
            elif policy["sp"] == "quarantine" and policy["pct"] != "100":
                vulnerable = True
                vulnerabilities.append(
                    "DMARC subdomain policy is quarantine-only with partial enforcement (pct=" + policy["pct"] + ")"
                )
            elif not policy["sp"] == "quarantine" and not policy["sp"] == "reject":
                vulnerable = True
                vulnerabilities.append("DMARC subdomain policy action invalid (sp='" + policy["sp"] + "')")

            if policy["pct"] != "100":
                vulnerable = True
                vulnerabilities.append("DMARC policy does not apply to all email (pct=" + policy["pct"] + ")")

            # TODO: vulnerability event if adkim is not s ?
            if policy["adkim"] != "r" and policy["adkim"] != "s":
                vulnerable = True
                vulnerabilities.append(
                    "DMARC policy DKIM Identifier Alignment mode is invalid (adkim=" + policy["adkim"] + ")"
                )

            # TODO: vulnerability event if aspf is not s ?
            if policy["aspf"] != "r" and policy["aspf"] != "s":
                vulnerable = True
                vulnerabilities.append(
                    "DMARC policy SPF Identifier Alignment mode is invalid (adkim=" + policy["adkim"] + ")"
                )

            if policy["ruf"] != "":
                # RFC-7489: fo tag is only utilised if ruf contains some kind of destination
                fo = {
                    "0": True,  # Generate a DMARC failure report if all underlying authentication mechanisms fail to produce an aligned "pass" result.
                    "1": False,  # Generate a DMARC failure report if any underlying authentication mechanism produced something other than an aligned "pass" result.
                    "d": False,  # Generate a DKIM failure report if the message had a signature that failed evaluation, regardless of its alignment.
                    "s": False,  # Generate an SPF failure report if the message failed SPF evaluation, regardless of its alignment.
                }
                fo_valid = True

                if policy["fo"] == "":
                    valid = False
                    reasons.append("fo option is an empty string")
                    fo_valid = False
                else:
                    for c in policy["fo"].split(":"):
                        # checks that each option is in the supported set of 0, 1, d or s
                        fo[c] = True

                        if not c in fo:
                            fo_valid = False
                            valid = False
                            reasons.append(f"fo option contains unsupported option '{c}'")

                if fo_valid == False:
                    vulnerable = True
                    vulnerabilities.append("DMARC Forensic Option set is invalid (fo=" + policy["fo"] + ")")

                # TODO: emit vulnerability event if the default of 0 is the only option set?
                # e.g. minimal reporting which can provide the opportunity to test spoofing without triggering reports ?

            if policy["rf"] != "afrf":
                # NOTE: only afrf currently supported, "xml" or "json" etc would likely result in an invalid/unenforced policy.
                vulnerable = True
                vulnerabilities.append("DMARC Reporting Format is invalid (rf=" + policy["rf"] + ")")

            try:
                ri = int(policy["ri"])
                # NOTE: Reporting Intervals less than 1 hour (3600 seconds) or greater than 24 hours
                # (86400 seconds) may not be supported by mail servers and behaviour may be inconsistent,
                # e.g. aggregate reports may not be sent at all.
                #
                # "ri: Indicates a request to Receivers to generate aggregate reports separated by no
                # more than the requested number of seconds.  DMARC implementations MUST be able to
                # provide daily reports and SHOULD be able to provide hourly reports when requested.
                # However, anything other than a daily report is understood to be accommodated on a
                # best-effort basis."

                # Should these actually be considered as a vulnerability, or simply a misconfiguration/possible problem?
                if ri < 3600:
                    vulnerable = True
                    vulnerabilities.append(
                        "DMARC Reporting Interval is less than 3600 seconds (1 hour) (ri=" + policy["ri"] + ")"
                    )
                elif ri > 86400:
                    vulnerable = True
                    vulnerabilities.append(
                        "DMARC Reporting Interval is greater than 86400 seconds (24 hours) (ri=" + policy["ri"] + ")"
                    )

            except ValueError:
                valid = False
                reasons.append("ri value is not an integer")
                vulnerable = True
                vulnerabilities.append("Reporting Interval is not an integer (ri=" + policy["ri"] + ")")

        elif answer.lower().startswith("v=dmarc"):
            dmarc = True
            valid = False
            reasons.append("invalid format record")
            reasons.append("regex match failed")

            vulnerable = True
            vulnerabilities.append(
                "DMARC policy is not parsable and may not be utilised by third parties, domain may be spoofable to some destinations"
            )
        else:
            # Non-DMARC records do not constitute a vulnerability as they *should* be discard,
            # From RFC-7489: "Records that do not start with a "v=" tag that identifies the current version of DMARC are discarded."
            dmarc = False
            valid = False
            reasons.append("invalid format record")
            reasons.append("non-DMARC related response, possible wildcard TXT record")

        return {
            "dmarc": dmarc,
            "valid": valid,
            "reasons": reasons,
            "vulnerable": vulnerable,
            "vulnerabilities": vulnerabilities,
        }

    async def handle_event(self, event):
        rdtype = "TXT"
        tags = ["dmarc-record"]
        hostname = f"_dmarc.{event.host}"

        r = await self.helpers.resolve_raw(hostname, type=rdtype)

        if r:
            raw_results, errors = r

            answer_count = 0
            dmarc_count = 0
            dmarc_valid_count = 0
            dmarc_vulnerable_count = 0

            for answer in raw_results:
                answer_count = answer_count + 1
                # we need to fix TXT data that may have been split across two different rdata's
                # e.g. we will get a single string, but within that string we may have two parts such as:
                # answer = '"part 1 that was really long" "part 2 that did not fit in part 1"'
                # NOTE: the leading and trailing double quotes are essential as part of a raw DNS TXT record, or another record type that contains a free form text string as a component.
                s = answer.to_text().strip('"').replace('" "', "")

                if self.emit_raw_dns_records:
                    await self.emit_event(
                        {"host": hostname, "type": rdtype, "answer": answer.to_text()},
                        "RAW_DNS_RECORD",
                        parent=event,
                        tags=tags.append(f"{rdtype.lower()}-record"),
                        context=f"{rdtype} lookup on {hostname} produced {{event.type}}",
                    )

                result = await self.validateDMARC(event, hostname, s, tags)

                if result["dmarc"] == True:
                    dmarc_count = dmarc_count + 1

                if result["valid"] == True:
                    dmarc_valid_count = dmarc_valid_count + 1

                if result["vulnerable"] == True:
                    dmarc_vulnerable_count = dmarc_vulnerable_count + 1

                if self.emit_vulnerabilities == True and result["vulnerable"] == True:
                    severity = "HIGH"
                    description = ", ".join(result["vulnerabilities"])
                    self.debug(f"VULN: {hostname} = '{description}'")
                    await self.emit_event(
                        {
                            "host": hostname,
                            "severity": severity,
                            "description": description,
                        },
                        "VULNERABILITY",
                        parent=event,
                        tags=tags.append(f"vulnerability"),
                        context=f"DMARC policy inspection against {hostname} identified one or more vulnerabilities in answer {answer_count} '{s}'. Potential for domain spoofing exists.",
                    )

            if dmarc_count == 0:
                await self.emit_event(
                    {
                        "host": hostname,
                        "severity": "HIGH",
                        "description": f"DMARC policy absent for this domain",
                    },
                    "VULNERABILITY",
                    parent=event,
                    tags=tags.append(f"vulnerability"),
                    context=f"TXT requests against {hostname} returned {answer_count} answers, of which {dmarc_count} were DMARC policies. The target domain can be spoofed.",
                )

            if dmarc_count > 1 and dmarc_vulnerable_count > 0 and self.emit_vulnerabilities == True:
                await self.emit_event(
                    {
                        "host": hostname,
                        "severity": "HIGH",
                        "description": "multiple DMARC policies have been published with at least one vulnerable policy present",
                    },
                    "VULNERABILITY",
                    parent=event,
                    tags=tags.append(f"vulnerability"),
                    context=f"TXT requests against {hostname} returned {answer_count} answers, of which {dmarc_count} were DMARC policies, {dmarc_valid_count} appear to be valid and {dmarc_vulnerable_count} is vulnerable. Policy enforcement by MTA's may be inconsitent. Potential for domain spoofing exists.",
                )


# EOF

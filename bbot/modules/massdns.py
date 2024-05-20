import re
import json
import random
import asyncio
import subprocess

from bbot.modules.templates.subdomain_enum import subdomain_enum


class massdns(subdomain_enum):
    """
    This is BBOT's flagship subdomain enumeration module.

    It uses massdns to brute-force subdomains.
    At the end of a scan, it will leverage BBOT's word cloud to recursively discover target-specific subdomain mutations.

    Each subdomain discovered via mutations is tagged with the "mutation" tag. This tag indicates the depth at which
    the mutation was found. I.e. the first mutation will be tagged "mutation-1". The second one (a mutation of a
    mutation) will be "mutation-2". Mutations of mutations of mutations will be "mutation-3", etc.

    This is especially use for bug bounties because it enables you to recognize distant/rare subdomains at a glance.
    Subdomains with higher mutation levels are more likely to be distant/rare or never-before-seen.
    """

    flags = ["subdomain-enum", "passive", "aggressive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Brute-force subdomains with massdns (highly effective)",
        "created_date": "2023-03-29",
        "author": "@TheTechromancer"
        }
    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "max_resolvers": 1000,
        "max_mutations": 500,
        "max_depth": 5,
    }
    options_desc = {
        "wordlist": "Subdomain wordlist URL",
        "max_resolvers": "Number of concurrent massdns resolvers",
        "max_mutations": "Max number of smart mutations per subdomain",
        "max_depth": "How many subdomains deep to brute force, i.e. 5.4.3.2.1.evilcorp.com",
    }
    subdomain_file = None
    deps_ansible = [
        {
            "name": "install dev tools",
            "package": {"name": ["gcc", "git", "make"], "state": "present"},
            "become": True,
            "ignore_errors": True,
        },
        {
            "name": "Download massdns source code",
            "git": {
                "repo": "https://github.com/blechschmidt/massdns.git",
                "dest": "#{BBOT_TEMP}/massdns",
                "single_branch": True,
                "version": "master",
            },
        },
        {
            "name": "Build massdns (Linux)",
            "command": {"chdir": "#{BBOT_TEMP}/massdns", "cmd": "make", "creates": "#{BBOT_TEMP}/massdns/bin/massdns"},
            "when": "ansible_facts['system'] == 'Linux'",
        },
        {
            "name": "Build massdns (non-Linux)",
            "command": {
                "chdir": "#{BBOT_TEMP}/massdns",
                "cmd": "make nolinux",
                "creates": "#{BBOT_TEMP}/massdns/bin/massdns",
            },
            "when": "ansible_facts['system'] != 'Linux'",
        },
        {
            "name": "Install massdns",
            "copy": {"src": "#{BBOT_TEMP}/massdns/bin/massdns", "dest": "#{BBOT_TOOLS}/", "mode": "u+x,g+x,o+x"},
        },
    ]
    reject_wildcards = "strict"
    _qsize = 10000

    digit_regex = re.compile(r"\d+")

    async def setup(self):
        self.found = dict()
        self.mutations_tried = set()
        self.source_events = self.helpers.make_target()
        self.subdomain_file = await self.helpers.wordlist(self.config.get("wordlist"))
        self.subdomain_list = set(self.helpers.read_file(self.subdomain_file))

        ms_on_prem_string_file = self.helpers.wordlist_dir / "ms_on_prem_subdomains.txt"
        ms_on_prem_strings = set(self.helpers.read_file(ms_on_prem_string_file))
        self.subdomain_list.update(ms_on_prem_strings)

        self.max_resolvers = self.config.get("max_resolvers", 1000)
        self.max_mutations = self.config.get("max_mutations", 500)
        self.max_depth = max(1, self.config.get("max_depth", 5))
        nameservers_url = (
            "https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/nameservers.txt"
        )
        self.resolver_file = await self.helpers.wordlist(
            nameservers_url,
            cache_hrs=24 * 7,
        )
        self.devops_mutations = list(self.helpers.word_cloud.devops_mutations)
        self.mutation_run = 1

        self.resolve_and_emit_queue = asyncio.Queue()
        self.resolve_and_emit_task = asyncio.create_task(self.resolve_and_emit())
        return await super().setup()

    async def filter_event(self, event):
        query = self.make_query(event)
        eligible, reason = await self.eligible_for_enumeration(event)

        # limit brute force depth
        subdomain_depth = self.helpers.subdomain_depth(query) + 1
        if subdomain_depth > self.max_depth:
            eligible = False
            reason = f"subdomain depth of *.{query} ({subdomain_depth}) > max_depth ({self.max_depth})"

        # don't brute-force things that look like autogenerated PTRs
        if self.helpers.is_ptr(query):
            eligible = False
            reason = f'"{query}" looks like an autogenerated PTR'

        if eligible:
            self.add_found(event)
        # reject if already processed
        if self.already_processed(query):
            return False, f'Query "{query}" was already processed'

        if eligible:
            self.processed.add(hash(query))
            return True, reason
        return False, reason

    async def handle_event(self, event):
        query = self.make_query(event)
        self.source_events.add_target(event)
        self.info(f"Brute-forcing subdomains for {query} (source: {event.data})")
        results = await self.massdns(query, self.subdomain_list)
        await self.resolve_and_emit_queue.put((results, event, None))

    def abort_if(self, event):
        if not event.scope_distance == 0:
            return True, "event is not in scope"
        if "wildcard" in event.tags:
            return True, "event is a wildcard"
        if "unresolved" in event.tags:
            return True, "event is unresolved"
        return False, ""

    def already_processed(self, hostname):
        if hash(hostname) in self.processed:
            return True
        return False

    async def massdns(self, domain, subdomains):
        subdomains = list(subdomains)

        domain_wildcard_rdtypes = set()
        for _domain, rdtypes in (await self.helpers.is_wildcard_domain(domain)).items():
            for rdtype, results in rdtypes.items():
                if results:
                    domain_wildcard_rdtypes.add(rdtype)
        if any([r in domain_wildcard_rdtypes for r in ("A", "CNAME")]):
            self.info(
                f"Aborting massdns on {domain} because it's a wildcard domain ({','.join(domain_wildcard_rdtypes)})"
            )
            self.found.pop(domain, None)
            return []
        else:
            self.log.trace(f"{domain}: A is not in domain_wildcard_rdtypes:{domain_wildcard_rdtypes}")

        # before we start, do a canary check for wildcards
        abort_msg = f"Aborting massdns on {domain} due to false positive"
        canary_result = await self._canary_check(domain)
        if canary_result:
            self.info(abort_msg + f": {canary_result}")
            return []
        else:
            self.log.trace(f"Canary result for {domain}: {canary_result}")

        results = []
        async for hostname, ip, rdtype in self._massdns(domain, subdomains):
            # allow brute-forcing of wildcard domains
            # this is dead code but it's kinda cool so it can live here
            if rdtype in domain_wildcard_rdtypes:
                # skip wildcard checking on multi-level subdomains for performance reasons
                stem = hostname.split(domain)[0].strip(".")
                if "." in stem:
                    self.debug(f"Skipping {hostname}:A because it may be a wildcard (reason: performance)")
                    continue
                wildcard_rdtypes = await self.helpers.is_wildcard(hostname, ips=(ip,), rdtype=rdtype)
                if rdtype in wildcard_rdtypes:
                    self.debug(f"Skipping {hostname}:{rdtype} because it's a wildcard")
                    continue
            results.append(hostname)

        # do another canary check for good measure
        if len(results) > 50:
            canary_result = await self._canary_check(domain)
            if canary_result:
                self.info(abort_msg + f": {canary_result}")
                return []
            else:
                self.log.trace(f"Canary result for {domain}: {canary_result}")

        # abort if there are a suspiciously high number of results
        # (the results are over 2000, and this is more than 20 percent of the input size)
        if len(results) > 2000:
            if len(results) / len(subdomains) > 0.2:
                self.info(
                    f"Aborting because the number of results ({len(results):,}) is suspiciously high for the length of the wordlist ({len(subdomains):,})"
                )
                return []
            else:
                self.info(
                    f"{len(results):,} results returned from massdns against {domain} (wordlist size = {len(subdomains):,})"
                )

        # everything checks out
        return results

    async def resolve_and_emit(self):
        """
        When results are found, they are placed into self.resolve_and_emit_queue.
        The purpose of this function (which is started as a task in the module's setup()) is to consume results from
        the queue, resolve them, and if they resolve, emit them.

        This exists to prevent disrupting the scan with huge batches of DNS resolutions.
        """
        while 1:
            results, source_event, tags = await self.resolve_and_emit_queue.get()
            self.verbose(f"Resolving batch of {len(results):,} results")
            async with self._task_counter.count(f"{self.name}.resolve_and_emit()"):
                async for hostname, r in self.helpers.resolve_batch(results, type=("A", "CNAME")):
                    if not r:
                        self.debug(f"Discarding {hostname} because it didn't resolve")
                        continue
                    self.add_found(hostname)
                    if source_event is None:
                        source_event = self.source_events.get(hostname)
                        if source_event is None:
                            self.warning(f"Could not correlate source event from: {hostname}")
                            source_event = self.scan.root_event
                    kwargs = {"abort_if": self.abort_if, "tags": tags}
                    await self.emit_event(hostname, "DNS_NAME", source_event, **kwargs)

    @property
    def running(self):
        return super().running or self.resolve_and_emit_queue.qsize() > 0

    async def _canary_check(self, domain, num_checks=50):
        random_subdomains = list(self.gen_random_subdomains(num_checks))
        self.verbose(f"Testing {len(random_subdomains):,} canaries against {domain}")
        canary_results = [h async for h, d, r in self._massdns(domain, random_subdomains)]
        self.log.trace(f"canary results for {domain}: {canary_results}")
        resolved_canaries = self.helpers.resolve_batch(canary_results)
        self.log.trace(f"resolved canary results for {domain}: {canary_results}")
        async for query, result in resolved_canaries:
            if result:
                await resolved_canaries.aclose()
                result = f"{query}:{result}"
                self.log.trace(f"Found false positive: {result}")
                return result
        self.log.trace(f"Passed canary check for {domain}")
        return False

    async def _massdns(self, domain, subdomains):
        """
        {
          "name": "www.blacklanternsecurity.com.",
          "type": "A",
          "class": "IN",
          "status": "NOERROR",
          "data": {
            "answers": [
              {
                "ttl": 3600,
                "type": "CNAME",
                "class": "IN",
                "name": "www.blacklanternsecurity.com.",
                "data": "blacklanternsecurity.github.io."
              },
              {
                "ttl": 3600,
                "type": "A",
                "class": "IN",
                "name": "blacklanternsecurity.github.io.",
                "data": "185.199.108.153"
              }
            ]
          },
          "resolver": "168.215.165.186:53"
        }
        """
        if self.scan.stopping:
            return

        command = (
            "massdns",
            "-r",
            self.resolver_file,
            "-s",
            self.max_resolvers,
            "-t",
            "A",
            "-o",
            "J",
            "-q",
        )
        subdomains = self.gen_subdomains(subdomains, domain)
        hosts_yielded = set()
        async for line in self.run_process_live(command, stderr=subprocess.DEVNULL, input=subdomains):
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.debug(f"Failed to decode line: {line}")
                continue
            answers = j.get("data", {}).get("answers", [])
            if type(answers) == list and len(answers) > 0:
                answer = answers[0]
                hostname = answer.get("name", "").strip(".").lower()
                if hostname.endswith(f".{domain}"):
                    data = answer.get("data", "")
                    rdtype = answer.get("type", "").upper()
                    # avoid garbage answers like this:
                    # 8AAAA queries have been locally blocked by dnscrypt-proxy/Set block_ipv6 to false to disable this feature
                    if data and rdtype and not " " in data:
                        hostname_hash = hash(hostname)
                        if hostname_hash not in hosts_yielded:
                            hosts_yielded.add(hostname_hash)
                            yield hostname, data, rdtype

    async def finish(self):
        found = sorted(self.found.items(), key=lambda x: len(x[-1]), reverse=True)
        # if we have a lot of rounds to make, don't try mutations on less-populated domains
        trimmed_found = []
        if found:
            avg_subdomains = sum([len(subdomains) for domain, subdomains in found[:50]]) / len(found[:50])
            for i, (domain, subdomains) in enumerate(found):
                # accept domains that are in the top 50 or have more than 5 percent of the average number of subdomains
                if i < 50 or (len(subdomains) > 1 and len(subdomains) >= (avg_subdomains * 0.05)):
                    trimmed_found.append((domain, subdomains))
                else:
                    self.verbose(
                        f"Skipping mutations on {domain} because it only has {len(subdomains):,} subdomain(s) (avg: {avg_subdomains:,})"
                    )

        base_mutations = set()
        found_mutations = False
        try:
            for i, (domain, subdomains) in enumerate(trimmed_found):
                self.verbose(f"{domain} has {len(subdomains):,} subdomains")
                # keep looping as long as we're finding things
                while 1:
                    max_mem_percent = 90
                    mem_status = self.helpers.memory_status()
                    # abort if we don't have the memory
                    mem_percent = mem_status.percent
                    if mem_percent > max_mem_percent:
                        free_memory = mem_status.available
                        free_memory_human = self.helpers.bytes_to_human(free_memory)
                        assert (
                            False
                        ), f"Cannot proceed with DNS mutations because system memory is at {mem_percent:.1f}% ({free_memory_human} remaining)"

                    query = domain
                    domain_hash = hash(domain)
                    if self.scan.stopping:
                        return

                    mutations = set(base_mutations)

                    def add_mutation(_domain_hash, m):
                        h = hash((_domain_hash, m))
                        if h not in self.mutations_tried:
                            self.mutations_tried.add(h)
                            mutations.add(m)

                    num_base_mutations = len(base_mutations)
                    self.debug(f"Base mutations for {domain}: {num_base_mutations:,}")

                    # try every subdomain everywhere else
                    for _domain, _subdomains in found:
                        if _domain == domain:
                            continue
                        for s in _subdomains:
                            first_segment = s.split(".")[0]
                            # skip stuff with lots of numbers (e.g. PTRs)
                            if self.has_excessive_digits(first_segment):
                                continue
                            add_mutation(domain_hash, first_segment)
                            for word in self.helpers.extract_words(
                                first_segment, word_regexes=self.helpers.word_cloud.dns_mutator.extract_word_regexes
                            ):
                                add_mutation(domain_hash, word)

                    num_massdns_mutations = len(mutations) - num_base_mutations
                    self.debug(f"Mutations from previous subdomains for {domain}: {num_massdns_mutations:,}")

                    # numbers + devops mutations
                    for mutation in self.helpers.word_cloud.mutations(
                        subdomains, cloud=False, numbers=3, number_padding=1
                    ):
                        for delimiter in ("", ".", "-"):
                            m = delimiter.join(mutation).lower()
                            add_mutation(domain_hash, m)

                    num_word_cloud_mutations = len(mutations) - num_massdns_mutations
                    self.debug(f"Mutations added by word cloud for {domain}: {num_word_cloud_mutations:,}")

                    # special dns mutator
                    self.debug(
                        f"DNS Mutator size: {len(self.helpers.word_cloud.dns_mutator):,} (limited to {self.max_mutations:,})"
                    )
                    for subdomain in self.helpers.word_cloud.dns_mutator.mutations(
                        subdomains, max_mutations=self.max_mutations
                    ):
                        add_mutation(domain_hash, subdomain)

                    num_mutations = len(mutations) - num_word_cloud_mutations
                    self.debug(f"Mutations added by DNS Mutator: {num_mutations:,}")

                    if mutations:
                        self.info(f"Trying {len(mutations):,} mutations against {domain} ({i+1}/{len(found)})")
                        results = list(await self.massdns(query, mutations))
                        if results:
                            await self.resolve_and_emit_queue.put((results, None, [f"mutation-{self.mutation_run}"]))
                            found_mutations = True
                            continue
                    break
        except AssertionError as e:
            self.warning(e)

        if found_mutations:
            self.mutation_run += 1

    def add_found(self, host):
        if not isinstance(host, str):
            host = host.data
        if self.helpers.is_subdomain(host):
            subdomain, domain = host.split(".", 1)
            is_ptr = self.helpers.is_ptr(subdomain)
            in_scope = self.scan.in_scope(domain)
            if in_scope and not is_ptr:
                try:
                    self.found[domain].add(subdomain)
                except KeyError:
                    self.found[domain] = set((subdomain,))

    async def gen_subdomains(self, prefixes, domain):
        for p in prefixes:
            d = f"{p}.{domain}"
            yield d

    def gen_random_subdomains(self, n=50):
        delimiters = (".", "-")
        lengths = list(range(3, 8))
        for i in range(0, max(0, n - 5)):
            d = delimiters[i % len(delimiters)]
            l = lengths[i % len(lengths)]
            segments = list(random.choice(self.devops_mutations) for _ in range(l))
            segments.append(self.helpers.rand_string(length=8, digits=False))
            subdomain = d.join(segments)
            yield subdomain
        for _ in range(5):
            yield self.helpers.rand_string(length=8, digits=False)

    def has_excessive_digits(self, d):
        """
        Identifies dns names with excessive numbers, e.g.:
            - w1-2-3.evilcorp.com
            - ptr1234.evilcorp.com
        """
        digits = self.digit_regex.findall(d)
        excessive_digits = len(digits) > 2
        long_digits = any(len(d) > 3 for d in digits)
        if excessive_digits or long_digits:
            return True
        return False

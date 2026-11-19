from phishlens.received import hop_delays, parse_hops


def test_hops_come_back_origin_first():
    chain = [
        "from mx.example.com by final.example.com with ESMTP id b; "
        "Wed, 18 Nov 2026 10:05:00 +0200",
        "from origin.example.net by mx.example.com with ESMTP id a; "
        "Wed, 18 Nov 2026 10:00:00 +0200",
    ]
    hops = parse_hops(chain)
    assert [h.index for h in hops] == [0, 1]
    assert hops[0].from_host == "origin.example.net"
    assert hops[0].by_host == "mx.example.com"
    assert hops[1].by_host == "final.example.com"


def test_timestamps_are_timezone_aware():
    hops = parse_hops(["from a.example by b.example; Wed, 18 Nov 2026 10:00:00 +0200"])
    assert hops[0].timestamp is not None
    assert hops[0].timestamp.tzinfo is not None
    assert hops[0].timestamp.isoformat().endswith("+02:00")


def test_delays_between_hops():
    chain = [
        "from mx.example.com by final.example.com; Wed, 18 Nov 2026 10:05:00 +0000",
        "from origin.example.net by mx.example.com; Wed, 18 Nov 2026 10:00:00 +0000",
    ]
    delays = hop_delays(parse_hops(chain))
    assert delays == [None, 300.0]


def test_negative_delay_detectable():
    chain = [
        "from mx.example.com by final.example.com; Wed, 18 Nov 2026 09:55:00 +0000",
        "from origin.example.net by mx.example.com; Wed, 18 Nov 2026 10:00:00 +0000",
    ]
    delays = hop_delays(parse_hops(chain))
    assert delays[1] == -300.0


def test_unparseable_timestamp_is_none_not_crash():
    hops = parse_hops(["from a.example by b.example; not a date"])
    assert hops[0].timestamp is None
    hops = parse_hops(["from a.example by b.example with ESMTP id x"])
    assert hops[0].timestamp is None

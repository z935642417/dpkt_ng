# -*- coding: utf-8 -*-
"""Route topology reconstruction from routing protocol captures."""
from __future__ import absolute_import, print_function
import json
import socket
import struct


class Router(object):
    """Unified router representation."""
    def __init__(self, rid):
        self.id = str(rid)
        self.name = ''
        self.asn = 0
        self.area = ''
        self.protocols = set()

    def __repr__(self):
        return 'Router(%s%s%s)' % (self.id, ' AS' + str(self.asn) if self.asn else '',
                                   ' area=' + self.area if self.area else '')


class Link(object):
    """Unidirectional or bidirectional link."""
    def __init__(self, src, dst, metric=1, link_type='p2p', protocol=''):
        self.src_id = str(src); self.dst_id = str(dst)
        self.metric = metric; self.link_type = link_type; self.protocol = protocol

    def __repr__(self):
        return 'Link(%s -> %s, metric=%d)' % (self.src_id, self.dst_id, self.metric)


class Prefix(object):
    """Routable network prefix."""
    def __init__(self, network, mask=32, nexthop='', metric=0, protocol='', origin='internal'):
        self.network = str(network); self.mask = int(mask)
        self.nexthop = str(nexthop); self.metric = int(metric)
        self.protocol = protocol; self.origin = origin

    def __repr__(self):
        return 'Prefix(%s/%d via %s [%s])' % (self.network, self.mask, self.nexthop, self.protocol)


class Area(object):
    def __init__(self, aid):
        self.id = str(aid); self.routers = set()


def _inet_to_str(inet):
    """Convert bytes IP to string."""
    if isinstance(inet, str):
        return inet
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except (ValueError, struct.error):
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except (ValueError, struct.error):
            return str(inet)


class TopologyBuilder(object):
    """Build unified topology from routing protocol packets."""

    def __init__(self):
        self.routers = {}      # {rid: Router}
        self.links = []        # [Link]
        self.prefixes = []     # [Prefix]
        self.areas = {}        # {aid: Area}
        self._bgp_stream = None  # StreamReassembler for BGP TCP:179

    # ---- Public API ----
    def process_packet(self, ip, eth=None):
        """Process one parsed IP packet. Auto-dispatches to protocol extractors."""
        from . import ospf as ospf_mod, eigrp as eigrp_mod
        from . import rip as rip_mod, bgp as bgp_mod
        from . import isis as isis_mod, tcp as tcp_mod, udp as udp_mod

        pkt = ip.data
        # OSPF (IP proto 89)
        if isinstance(pkt, ospf_mod.OSPF):
            self._extract_ospf(ip, pkt)
        # EIGRP (IP proto 88)
        elif isinstance(pkt, eigrp_mod.EIGRP):
            self._extract_eigrp(ip, pkt)
        # RIP (UDP 520)
        elif isinstance(pkt, udp_mod.UDP) and (pkt.sport == 520 or pkt.dport == 520):
            try:
                self._extract_rip(ip, rip_mod.RIP(pkt.data))
            except Exception:
                pass
        # BGP (TCP 179) - use stream reassembly
        elif isinstance(pkt, tcp_mod.TCP) and (pkt.sport == 179 or pkt.dport == 179):
            self._feed_bgp_tcp(ip, pkt)
        # IS-IS (LLC dsap=0xfe)
        elif eth is not None:
            from . import llc as llc_mod
            if isinstance(eth.data, llc_mod.LLC):
                try:
                    isis_pkt = isis_mod.ISIS(eth.data.data)
                    self._extract_isis(isis_pkt)
                except Exception:
                    pass

    def build(self):
        """Finalize: flush BGP stream reassembly."""
        if self._bgp_stream:
            for conn_id in list(self._bgp_stream.connections.keys()):
                conn = self._bgp_stream[conn_id]
                data = conn.c2s.get_data() or conn.s2c.get_data()
                if data:
                    try:
                        from . import bgp as bgp_mod
                        bgp_msg = bgp_mod.BGP(data)
                        self._extract_bgp(conn_id, bgp_msg)
                    except Exception:
                        pass

    def get_topology(self):
        return {'routers': list(self.routers.values()), 'links': self.links, 'prefixes': self.prefixes}

    def get_prefix_table(self):
        return self.prefixes

    def export_json(self, filepath):
        with open(filepath, 'w') as f:
            json.dump({
                'routers': [{'id': r.id, 'name': r.name, 'asn': r.asn, 'area': r.area} for r in self.routers.values()],
                'links': [{'src': l.src_id, 'dst': l.dst_id, 'metric': l.metric, 'type': l.link_type, 'protocol': l.protocol} for l in self.links],
                'prefixes': [{'net': p.network, 'mask': p.mask, 'nh': p.nexthop, 'metric': p.metric, 'protocol': p.protocol, 'origin': p.origin} for p in self.prefixes],
            }, f, indent=2)

    # ---- Protocol Extractors ----
    def _get_router(self, rid, name='', area='', asn=0):
        if rid not in self.routers:
            self.routers[rid] = Router(rid)
        r = self.routers[rid]
        if name: r.name = name
        if area: r.area = area
        if asn: r.asn = asn
        return r

    def _extract_ospf(self, ip, ospf):
        """OSPF: process LSU LSAs for links and prefixes."""
        from . import ospf as ospf_mod
        rid = _inet_to_str(ip.src)
        self._get_router(rid, area=str(ospf.area))
        router = self.routers[rid]; router.protocols.add('ospf')

        if isinstance(ospf.data, ospf_mod.OSPFv2LSU):
            for lsa in ospf.data.lsas:
                if isinstance(lsa, ospf_mod.LSARouter):
                    for link in lsa.links:
                        dst_id = str(link['id'])
                        lt = 'p2p' if link['type'] == 1 else 'transit' if link['type'] == 2 else 'stub'
                        self.links.append(Link(rid, dst_id, link['metric'], lt, 'ospf'))
                elif isinstance(lsa, ospf_mod.LSANetwork):
                    for r in lsa.routers:
                        rid2 = str(r)
                        self.links.append(Link(rid2, rid, 0, 'transit', 'ospf'))
                elif isinstance(lsa, ospf_mod.LSAASExternal):
                    nh = _inet_to_str(lsa.forwarding) if lsa.forwarding else rid
                    self.prefixes.append(Prefix('0.0.0.0', 0, nh, lsa.metric, 'ospf', 'external'))

    def _extract_isis(self, isis):
        """IS-IS: process LSP TLVs."""
        from . import isis as isis_mod
        if isinstance(isis.data, isis_mod.ISISLSPL1) or isinstance(isis.data, isis_mod.ISISLSPL2):
            lsp = isis.data
            # System ID from first 6 bytes of lsp_id
            sys_id = ':'.join('%02x' % (b if isinstance(b, int) else ord(b)) for b in lsp.lsp_id[:6])
            self._get_router(sys_id); self.routers[sys_id].protocols.add('isis')
            for tlv in lsp.tlvs:
                if isinstance(tlv, isis_mod.ISISEISReachTLV):
                    for ra in tlv.reachabilities:
                        nid = ra['neighbor']
                        dst = ':'.join('%02x' % (b if isinstance(b, int) else ord(b)) for b in nid[:6])
                        self.links.append(Link(sys_id, dst, ra['metric'], 'p2p', 'isis'))
                elif isinstance(tlv, isis_mod.ISISIPIntReachTLV):
                    for pfx in tlv.prefixes:
                        net = _inet_to_str(pfx['prefix'])
                        self.prefixes.append(Prefix(net, 32, sys_id, pfx['metric'], 'isis', 'internal'))

    def _feed_bgp_tcp(self, ip, tcp_pkt):
        """Feed BGP TCP stream to reassembler."""
        from . import stream as stream_mod
        if self._bgp_stream is None:
            self._bgp_stream = stream_mod.StreamReassembler(max_connections=1000)
        self._bgp_stream.feed(ip, tcp_pkt)

    def _extract_bgp(self, conn_id, bgp):
        """BGP: process UPDATE messages."""
        from . import bgp as bgp_mod
        if not hasattr(bgp, 'update') or not bgp.update:
            return
        # Mark BGP routers
        src_ip = conn_id[0] if isinstance(conn_id, tuple) else ''
        self._get_router(src_ip); self.routers[src_ip].protocols.add('bgp')
        # Extract NLRI from announced routes
        update = bgp.update
        if hasattr(update, 'announced'):
            for entry in update.announced:
                if hasattr(entry, 'prefix') and hasattr(entry, 'len'):
                    pfx = _inet_to_str(entry.prefix)
                    self.prefixes.append(Prefix(pfx, entry.len, src_ip, 0, 'bgp', 'igp'))
        # Also check MP_REACH_NLRI attributes
        if hasattr(update, 'attributes'):
            for attr in update.attributes:
                if hasattr(attr, 'mp_reach_nlri'):
                    mp = attr.mp_reach_nlri
                    if hasattr(mp, 'announced'):
                        for entry in mp.announced:
                            if hasattr(entry, 'prefix') and hasattr(entry, 'len'):
                                pfx = _inet_to_str(entry.prefix)
                                self.prefixes.append(Prefix(pfx, entry.len, src_ip, 0, 'bgp', 'igp'))

    def _extract_rip(self, ip, rip):
        """RIP: process Response entries."""
        src = _inet_to_str(ip.src)
        self._get_router(src); self.routers[src].protocols.add('rip')
        if hasattr(rip, 'rtes'):
            for entry in rip.rtes:
                net = _inet_to_str(entry.addr) if hasattr(entry, 'addr') else '0.0.0.0'
                mask = entry.subnet if hasattr(entry, 'subnet') else 24
                nh = _inet_to_str(entry.next_hop) if hasattr(entry, 'next_hop') else src
                self.prefixes.append(Prefix(net, mask, nh, entry.metric, 'rip', 'internal'))

    def _extract_eigrp(self, ip, eigrp):
        """EIGRP: process Update route TLVs."""
        src = _inet_to_str(ip.src)
        self._get_router(src, asn=eigrp.asn); self.routers[src].protocols.add('eigrp')
        if hasattr(eigrp.data, 'tlvs'):
            from . import eigrp as eigrp_mod
            for tlv in eigrp.data.tlvs:
                if isinstance(tlv, eigrp_mod.EIGRPInternalRouteTLV):
                    pfx = _inet_to_str(tlv.prefix) if tlv.prefix else '0.0.0.0'
                    self.prefixes.append(Prefix(pfx, tlv.prefix_length, src, tlv.delay, 'eigrp', 'internal'))


# ---- Tests ----
def test_topo_router():
    r = Router('10.0.0.1')
    r.name = 'R1'; r.asn = 100; r.area = '0.0.0.0'
    r.protocols.add('ospf')
    assert r.id == '10.0.0.1'
    assert r.name == 'R1'
    assert r.asn == 100
    assert r.area == '0.0.0.0'
    assert 'ospf' in r.protocols


def test_topo_link():
    l = Link('10.0.0.1', '10.0.0.2', 10, 'p2p', 'ospf')
    assert l.metric == 10
    assert l.protocol == 'ospf'


def test_topo_builder():
    b = TopologyBuilder()
    r = b._get_router('1.1.1.1', 'R1')
    assert r.name == 'R1'
    assert b.routers['1.1.1.1'] is r


def test_topo_prefix():
    p = Prefix('10.0.0.0', 24, '1.1.1.1', 100, 'ospf')
    assert p.network == '10.0.0.0'
    assert p.mask == 24


def test_topo_json_export(tmp_path):
    b = TopologyBuilder()
    b._get_router('1.1.1.1', 'R1')
    p = tmp_path / 'topo.json'
    b.export_json(str(p))
    assert p.exists()

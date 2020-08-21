from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, tcp, udp, icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto as inet
from ryu.lib import dpid as dpid_lib

from threading import Thread, Lock
from webob import Response
import importlib
import time
import os
import json

URL = "/firewall/api"
firewall_instance = 'firewall-api'

class Firewall(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    RULES_FILE = "rules{}"
    SUPPORTED_EXTENSIONS = ["json", "yaml", "toml"]

    IP_FIELDS = ["ip_proto", "ipv4_src", "ipv4_dst"]
    ICMP_FIELDS = ["icmpv4_type", "icmpv4_code"]
    TCP_FIELDS = ["tcp_src", "tcp_dst"]
    UDP_FIELDS = ["udp_src", "udp_dst"]

    MAX_SYN = 20

    SYN_MUTEX = Lock()
    API_MUTEX = Lock()

    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.parsed_rule_file = self.parse_rules()
        self.syn_track = {}
        self.stats_responses = []
        self.switches = []
        self.firewall_list = []

        wsgi = kwargs['wsgi']
        wsgi.register(FirewallRest, {firewall_instance: self})

        self.clean_thread = Thread(target=self.cleanup_syntrack)
        self.clean_thread.start()

    ###
    # Event Handlers
    ###

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_features_request(self, ev):
        ''' Handle OF Features Request '''
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.install_entry_miss_mod(datapath)
        self.logger.info("Datapath Added")
        self.logger.debug("-- DPID : {}".format(dpid_lib.dpid_to_str(datapath.id)))

        if dpid_lib.dpid_to_str(datapath.id) in self.parsed_rule_file:
            self.firewall_list.append(datapath)
            rules = self.parsed_rule_file[dpid_lib.dpid_to_str(datapath.id)]
            for r in rules['rules']:
                if any(ip_field in r for ip_field in self.IP_FIELDS):
                    r.update({'eth_type':0x0800})
                self.install_flow_mod(datapath, 10, self.ofmatch_from_dict(r), i_timeout=0)
        else:
            self.switches.append(datapath)  
            

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, ev):
        ''' Handle OF Packet In Event '''
        self.logger.debug("Packet In Event")
        datapath = ev.msg.datapath
        in_port = ev.msg.match["in_port"]
        data = ev.msg.data
        buffer_id = ev.msg.buffer_id
        parser = ev.msg.datapath.ofproto_parser

        self.add_l2_mapping(datapath.id, packet.Packet(data), in_port)
        out_actions, do_install = self.use_l2_mapping(datapath, packet.Packet(data))

        if do_install and datapath in self.switches:
            ofmatch = self.ofmatch_from_packet(datapath, packet.Packet(data), in_port)
            self.install_flow_mod(datapath, 1, ofmatch, out_actions)
        elif datapath in self.firewall_list:
            self.firewall(datapath, data, in_port, buffer_id, parser)

        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=out_actions, data=data)
        datapath.send_msg(out)
        return


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def handle_stats_response(self, ev):
        ''' Handle the OF FLow Stats Response '''
        # This is for Part 5
        flows = []
        for stat in ev.msg.body:
            self.logger.info("--------------------")
            self.logger.info("{} | packet count: {}".format(stat.match, stat.packet_count))
            flows.append(stat.packet_count)

        self.logger.info(flows)
        self.stats_responses = flows
    ###
    # Shared Functions
    ###

    def install_flow_mod(self, datapath, priority, match, actions=[], i_timeout=60, h_timeout=0):
        instructions = [datapath.ofproto_parser.OFPInstructionActions(
                            datapath.ofproto.OFPIT_APPLY_ACTIONS, 
                            actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=instructions, idle_timeout=i_timeout,
                                hard_timeout=h_timeout)
        datapath.send_msg(mod)
        self.logger.debug("Flow-Mod Written")

    def install_entry_miss_mod(self, datapath):
        match = datapath.ofproto_parser.OFPMatch()
        actions = [datapath.ofproto_parser.OFPActionOutput(
                        datapath.ofproto.OFPP_CONTROLLER, 
                        datapath.ofproto.OFPCML_NO_BUFFER)]
        self.install_flow_mod(datapath, 0, match, actions, 0, 0)

    def add_l2_mapping(self, datapath_id, pkt, in_port):
        eth_header = pkt.get_protocol(ethernet.ethernet)
        self.mac_to_port.setdefault(datapath_id, {})
        self.mac_to_port[datapath_id][eth_header.src] = in_port

    def use_l2_mapping(self, datapath, pkt):
        eth_header = pkt.get_protocol(ethernet.ethernet)
        out_port = datapath.ofproto.OFPP_FLOOD
        install = False
        if eth_header.dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth_header.dst]
            install = True
        return [datapath.ofproto_parser.OFPActionOutput(out_port)], install

    ###
    # Layer 4 Switch Functions
    ###

    def switch(self, datapath, in_port, data, buffer_id):
        ''' Handles L4 Switch Packet Ins '''
        raise NotImplementedError

    def ofmatch_from_packet(self, datapath, pkt, in_port):
        match_dict = {}
        match_dict["in_port"] = in_port
        eth_h = pkt.get_protocol(ethernet.ethernet)
        match_dict["eth_type"] = eth_h.ethertype
        match_dict["eth_src"] = eth_h.src
        match_dict["eth_dst"] = eth_h.dst
        if eth_h.ethertype == ether_types.ETH_TYPE_IP:
            ip_h = pkt.get_protocol(ipv4.ipv4)
            match_dict["ip_proto"] = ip_h.proto
            match_dict["ipv4_src"] = ip_h.src
            match_dict["ipv4_dst"] = ip_h.dst
            if ip_h.proto == inet.IPPROTO_TCP:
                tcp_h = pkt.get_protocol(tcp.tcp)
                match_dict["tcp_src"] = tcp_h.src_port
                match_dict["tcp_dst"] = tcp_h.dst_port
            elif ip_h.proto == inet.IPPROTO_UDP:
                udp_h = pkt.get_protocol(udp.udp)
                match_dict["udp_src"] = udp_h.src_port
                match_dict["udp_dst"] = udp_h.dst_port
            elif ip_h.proto == inet.IPPROTO_ICMP:
                icmp_h = pkt.get_protocol(icmp.icmp)
                match_dict["icmpv4_type"] = icmp_h.type
                match_dict["icmpv4_code"] = icmp_h.code
        return datapath.ofproto_parser.OFPMatch(**match_dict)

    ###
    # Firewall Functions
    ###

    def firewall(self, datapath, data, in_port, buffer_id, parser):
        ''' Handles Firwall Packet In Ins '''
        self.logger.info("got to firewall")
        pkt = packet.Packet(data)

        if pkt.get_protocol(tcp.tcp):
            tcp_p = pkt.get_protocol(tcp.tcp)
            if tcp_p.has_flags(tcp.TCP_SYN):
                self.logger.info("************GOT A SYN**************")
                ip_h = pkt.get_protocol(ipv4.ipv4)
                self.logger.info("IP HEADER: {}".format(ip_h))
                host = ip_h.src
                self.logger.info("SOURCE: {}".format(host))
                self.logger.info(self.syn_track)
                if host in self.syn_track:
                    self.logger.info("adds to counter")
                    self.SYN_MUTEX.acquire()
                    self.syn_track[host] = self.syn_track[host] + 1
                    self.SYN_MUTEX.release()
                else:
                    self.logger.info("making threads")
                    self.SYN_MUTEX.acquire()
                    self.syn_track[host] = 0
                    self.SYN_MUTEX.release()
                    thread = Thread(target = self.cleanup_syntrack, args=(host, datapath))
                    thread.start()              

    def parse_rules(self):
        '''parse the rule file(s) into the parsed_rule dict'''
        ## Part 2 ##
        with open('rules.json') as json_file:
            data = json.load(json_file)
            rules = data.get('datapath')

        return rules

    def ofmatch_from_dict(self, match_dict):
        ''' convert a dict/json rule to a match '''
        ## Part 2 # Part 5 ##
        return OFPMatch(**match_dict)

    def cleanup_syntrack(self, host, datapath):
        while True:
            ## Part 4 ##
            start_time = time.time()
            time_limit = 10
            while (time.time() - start_time) <= time_limit:
                self.SYN_MUTEX.acquire()
                self.logger.info("Syn Track: {}".format(self.syn_track))
                if self.syn_track[host] >= 20:
                    self.logger.info("INSTALLING BLOCK FOR {}".format(host))
                    temp_rule = self.ofmatch_from_dict({"ipv4_src":host, "eth_type":2048})
                    self.install_flow_mod(datapath, 20, temp_rule, [], i_timeout=0, h_timeout=60)
                self.SYN_MUTEX.release()
                time.sleep(.1)
            self.SYN_MUTEX.acquire()
            self.syn_track[host] = 0
            self.SYN_MUTEX.release()
            time.sleep(.1)

    def request_flow_stats(self, datapath, ofmatch):
        ## Part 5 ##
        ## Make and send the Flow Stats Request ##
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        #match = ofp_parser.OFPMatch(ofmatch)
        #self.logger.info(match)
        
        cookie = cookie_mask = 0
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY, cookie, cookie_mask, ofmatch)
        self.logger.info("sending request")
        datapath.send_msg(req)
        

    def get_stats_response(self):
        '''
        Handle async response for stats 
        Returns: A single int representing the packet count stat of a flow
        '''
        self.API_MUTEX.acquire()
        value = None
        try:
            if len(self.stats_responses) > 0:
                value = self.stats_responses.pop(0)
        finally:
            self.API_MUTEX.release()
            return value

class FirewallRest(ControllerBase):

    """
    Firewall REST API

    You should NOT modify this class!
    Look at the functions of the firewall being called and implement those if required!
    """

    MAX_TRIES = 30
    TRY_DELAY = .1

    STAT_BODY = {"packet_count": 0}
 
    def __init__(self, req, link, data, **config):
        super(FirewallRest, self).__init__(req, link, data, **config)
        self.fw = data[firewall_instance]

    @route('firewall', URL, methods=['GET'])
    def index(self, req):
        body = '{"hello": "world"}'
        return Response(content_type='application/json', charset='UTF-8', body=body)

    @route('firewall', URL+"/{dpid}", methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def is_dpid(self, req, **kwargs):
        body = '{"error": "datapath does not exist"}'
        try:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
            if self.fw.datapaths.get(dpid, None):
                body = '{"datapath functions": ["stats"]}'
        except:
            self.logger.debug("Could not find DPID provided")
        return Response(content_type='application/json', charset='UTF-8', body=body)
 
    @route('firewall', URL+"/{dpid}/stats", methods=['POST'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_flow_stats(self, req, **kwargs):
        try:
            req_body = req.json
            match = self.fw.ofmatch_from_dict(req_body)
        except:
            res_body = '{"error": "Could not parse data to ofmatch"}'
            return Response(content_type='application/json', charset='UTF-8', body=(res_body))

        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        dp = self.fw.datapaths.get(dpid)
        self.fw.request_flow_stats(dp, match)

        attempts = 0
        packet_count = None
        while attempts < self.MAX_TRIES and packet_count == None:
            packet_count = self.fw.get_stats_response()
            attempts+=1
            time.sleep(self.TRY_DELAY)

        if packet_count == None:
            res_body = {
                "error": "Switch did not provide stats response in time"
            }
            return Response(content_type='application/json', charset='UTF-8', body=json.dumps(res_body))

        res_body = {
            "packet_count": packet_count
        }
        return Response(content_type='application/json', charset='UTF-8', body=json.dumps(res_body))
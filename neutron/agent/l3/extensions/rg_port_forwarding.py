# Copyright (c) 2023 UnionTech
# All rights reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
from typing import Optional, List
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron_lib import constants
from neutron_lib.rpc import Connection
from neutron_lib.context import Context
from neutron_lib.agent import l3_extension

from neutron.agent.linux.ip_lib import IPDevice
from neutron.agent.l3.router_info import RouterInfo
from neutron.agent.linux.iptables_manager import IptablesManager

from neutron.api.rpc.handlers import resources_rpc
from neutron.api.rpc.callbacks import resources, events
from neutron.api.rpc.callbacks.consumer import registry

from neutron.common import coordination

from neutron.objects.ports import Port
from neutron.objects.router import Router
from neutron.objects.rg_port_forwarding import RGPortForwarding

LOG = logging.getLogger(__name__)

PORT_FORWARDING_PREFIX = 'rg_portforwarding-'
DEFAULT_PORT_FORWARDING_CHAIN = 'rg-pf'
PORT_FORWARDING_CHAIN_PREFIX = 'pf-'


def _get_port_forwarding_chain_name(pf_id):
    chain_name = PORT_FORWARDING_CHAIN_PREFIX + pf_id
    return chain_name[:constants.MAX_IPTABLES_CHAIN_LEN_WRAP]


class RGPortForwardingMapping(object):
    def __init__(self):
        self.managed_port_forwardings = {}
        self.router_pf_mapping = collections.defaultdict(set)

    @lockutils.synchronized('rg-port-forwarding-cache')
    def check_port_forwarding_changes(self, new_pf: RGPortForwarding) -> bool:
        old_pf = self.managed_port_forwardings.get(new_pf.id)
        return old_pf != new_pf

    @lockutils.synchronized('rg-port-forwarding-cache')
    def set_port_forwardings(self, port_forwardings: List[RGPortForwarding]):
        for port_forwarding in port_forwardings:
            self._set_router_port_forwarding(port_forwarding,
                                             port_forwarding.router_id)

    def _set_router_port_forwarding(self,
                                    port_forwarding: RGPortForwarding,
                                    router_id: str):
        self.router_pf_mapping[router_id].add(port_forwarding.id)
        self.managed_port_forwardings[port_forwarding.id] = port_forwarding

    @lockutils.synchronized('rg-port-forwarding-cache')
    def update_port_forwardings(self, port_forwardings):
        for port_forwarding in port_forwardings:
            self.managed_port_forwardings[port_forwarding.id] = port_forwarding

    @lockutils.synchronized('rg-port-forwarding-cache')
    def del_port_forwardings(self, port_forwardings):
        for port_forwarding in port_forwardings:
            if not self.managed_port_forwardings.get(port_forwarding.id):
                continue
            self.managed_port_forwardings.pop(port_forwarding.id)
            self.router_pf_mapping[port_forwarding.router_id].discard(
                port_forwarding.id)
            if not self.router_pf_mapping[port_forwarding.router_id]:
                self.router_pf_mapping.pop(port_forwarding.router_id)

    @lockutils.synchronized('rg-port-forwarding-cache')
    def clean_port_forwardings_by_router_id(self, router_id: str):
        pf_ids = self.router_pf_mapping.pop(router_id, [])
        for pf_id in pf_ids:
            self.managed_port_forwardings.pop(pf_id, None)


class RGPortForwardingAgentExtension(l3_extension.L3AgentExtension):
    SUPPORTED_RESOURCE_TYPES = [resources.RGPORTFORWARDING]

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def initialize(self, connection, driver_type):
        self.mapping = RGPortForwardingMapping()
        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        self._register_rpc_consumers()

    def _register_rpc_consumers(self):
        registry.register(self._handle_notification,
                          resources.RGPORTFORWARDING)
        self._connection = Connection()
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        topic = resources_rpc.resource_type_versioned_topic(
            resources.RGPORTFORWARDING)
        self._connection.create_consumer(topic, endpoints, fanout=True)
        self._connection.consume_in_threads()

    def _handle_notification(self, context: Context,
                             resource_type: str,
                             forwardings, event_type):
        for forwarding in forwardings:
            self._process_port_forwarding_event(
                context, forwarding, event_type)

    def _get_gw_port_and_ip(self,
                            ri: RouterInfo) -> (Optional[Port], Optional[str]):
        ex_gw_port = ri.get_ex_gw_port()
        ex_gw_port_ip = self._get_gw_port_ip(ex_gw_port)
        if not ex_gw_port_ip:
            LOG.error(f"Router {ri.router_id} external port "
                      f"{ex_gw_port['id']} does not have any IP addresses")
            return None, None
        return ex_gw_port, ex_gw_port_ip

    def _process_port_forwarding_event(self, context: Context,
                                       port_forwarding: RGPortForwarding,
                                       event_type: str):
        router_id = port_forwarding.router_id
        ri = self._get_router_info(router_id)
        if not self._check_if_need_process(ri, force=True):
            return

        ex_gw_port, ex_gw_port_ip = self._get_gw_port_and_ip(ri)
        if not ex_gw_port or not ex_gw_port_ip:
            return

        (interface_name, namespace,
         iptables_manager) = self._get_resource_by_router(ri, ex_gw_port)

        if event_type == events.CREATED:
            self._process_create([port_forwarding], ri, interface_name,
                                 ex_gw_port_ip, namespace, iptables_manager)
        elif event_type == events.UPDATED:
            self._process_update([port_forwarding], interface_name,
                                 ex_gw_port_ip, namespace, iptables_manager)
        elif event_type == events.DELETED:
            self._process_delete([port_forwarding], interface_name,
                                 ex_gw_port_ip, namespace, iptables_manager)

    def ha_state_change(self, context: Context, data: Router) -> None:
        pass

    def update_network(self, context: Context, data: dict) -> None:
        pass

    def add_router(self, context: Context, data: Router) -> None:
        LOG.info(f"call add_router for {data['id']}")
        self.process_port_forwarding(context, data)

    def update_router(self, context: Context, data: Router) -> None:
        LOG.info(f"call update_router for {data['id']}")
        self.process_port_forwarding(context, data)

    def delete_router(self, context: Context, data: Router) -> None:
        self.mapping.clean_port_forwardings_by_router_id(data['id'])

    def _get_router_info(self, router_id) -> Optional[RouterInfo]:
        router_info = self.agent_api.get_router_info(router_id)
        if router_info:
            return router_info
        LOG.debug("Router %s is not managed by this agent. "
                  "It was possibly deleted concurrently.", router_id)

    @staticmethod
    def _check_if_need_process(ri: RouterInfo, force: bool = False) -> bool:
        if not ri or not ri.get_ex_gw_port():
            return False

        if force:
            return True

        is_distributed = ri.router.get('distributed')
        agent_mode = ri.agent_conf.agent_mode
        if (is_distributed and
                agent_mode in [constants.L3_AGENT_MODE_DVR_NO_EXTERNAL,
                               constants.L3_AGENT_MODE_DVR]):
            # just support centralized cases
            return False

        if is_distributed and not ri.snat_namespace.exists():
            return False

        return True

    def process_port_forwarding(self, context: Context, data: Router):
        ri = self._get_router_info(data['id'])
        if not self._check_if_need_process(ri):
            return
        self.check_local_port_forwardings(context, ri)

    @staticmethod
    def _get_gw_port_ip(gw_port: dict) -> Optional[str]:
        fixed_ips = gw_port.get('fixed_ips', [])
        if not fixed_ips:
            return
        return fixed_ips[0].get('ip_address', None)

    @staticmethod
    def _get_resource_by_router(ri: RouterInfo, ex_gw_port: dict) -> (
            str, str, IptablesManager):
        is_distributed = ri.router.get('distributed')
        if is_distributed:
            interface_name = ri.get_snat_external_device_interface_name(
                ex_gw_port)
            namespace = ri.snat_namespace.name
            iptables_manager = ri.snat_iptables_manager
        else:
            interface_name = ri.get_external_device_interface_name(ex_gw_port)
            namespace = ri.ns_name
            iptables_manager = ri.iptables_manager

        return interface_name, namespace, iptables_manager

    def check_local_port_forwardings(self, context: Context, ri: RouterInfo):
        pfs = self.resource_rpc.bulk_pull(
            context, resources.RGPORTFORWARDING,
            filter_kwargs={'router_id': ri.router_id})
        if not pfs:
            return
        ex_gw_port, ex_gw_port_ip = self._get_gw_port_and_ip(ri)
        if not ex_gw_port_ip or not ex_gw_port_ip:
            return
        (interface_name, namespace,
         iptables_manager) = self._get_resource_by_router(ri, ex_gw_port)
        local_pfs = set(self.mapping.managed_port_forwardings.keys())
        new_pfs = []
        updated_pfs = []
        current_pfs = set()
        for pf in pfs:
            if pf.id in self.mapping.managed_port_forwardings:
                if self.mapping.check_port_forwarding_changes(pf):
                    updated_pfs.append(pf)
            else:
                new_pfs.append(pf)
            current_pfs.add(pf.id)

        remove_pf_ids_set = local_pfs - current_pfs
        remove_pfs = [self.mapping.managed_port_forwardings[pf_id]
                      for pf_id in remove_pf_ids_set]

        self._process_create(new_pfs, ri, interface_name, ex_gw_port_ip,
                             namespace, iptables_manager)

        self._process_update(updated_pfs, interface_name, ex_gw_port_ip,
                             namespace, iptables_manager)

        self._process_delete(remove_pfs, interface_name, ex_gw_port_ip,
                             namespace, iptables_manager)

    @staticmethod
    def _install_default_rules(iptables_manager: IptablesManager):
        default_rule = '-j %s-%s' % (iptables_manager.wrap_name,
                                     DEFAULT_PORT_FORWARDING_CHAIN)
        LOG.info(f'Add default chain {DEFAULT_PORT_FORWARDING_CHAIN}')
        LOG.info(f'Add default rule {default_rule}')
        iptables_manager.ipv4['nat'].add_chain(DEFAULT_PORT_FORWARDING_CHAIN)
        iptables_manager.ipv4['nat'].add_rule('PREROUTING', default_rule)
        iptables_manager.apply()

    @staticmethod
    def _get_rg_rules(port_forward: RGPortForwarding, wrap_name: str):
        chain_rule_list = []
        pf_chain_name = _get_port_forwarding_chain_name(port_forward.id)
        chain_rule_list.append(
            (DEFAULT_PORT_FORWARDING_CHAIN, f'-j {wrap_name}-{pf_chain_name}'))
        gw_ip_address = port_forward.gw_ip_address
        protocol = port_forward.protocol
        internal_ip_address = str(port_forward.internal_ip_address)
        internal_port = port_forward.internal_port
        external_port = port_forward.external_port
        chain_rule = (
            pf_chain_name,
            f'-d {gw_ip_address}/32 -p {protocol} -m {protocol} '
            f'--dport {external_port} '
            f'-j DNAT --to-destination {internal_ip_address}:{internal_port}'
        )
        chain_rule_list.append(chain_rule)
        return chain_rule_list

    def _rule_apply(self,
                    iptables_manager: IptablesManager,
                    port_forwarding: RGPortForwarding,
                    rule_tag: str):
        iptables_manager.ipv4['nat'].clear_rules_by_tag(rule_tag)
        if (DEFAULT_PORT_FORWARDING_CHAIN not in
                iptables_manager.ipv4['nat'].chains):
            self._install_default_rules(iptables_manager)

        for chain, rule in self._get_rg_rules(port_forwarding,
                                              iptables_manager.wrap_name):
            LOG.info(f'Add router gateway port forwarding '
                     f'rule {rule} in {chain}')
            if chain not in iptables_manager.ipv4['nat'].chains:
                iptables_manager.ipv4['nat'].add_chain(chain)
            iptables_manager.ipv4['nat'].add_rule(chain, rule, tag=rule_tag)

    def _store_local(self, pf_objs: List[RGPortForwarding], event_type: str):
        if event_type == events.CREATED:
            self.mapping.set_port_forwardings(pf_objs)
        elif event_type == events.UPDATED:
            self.mapping.update_port_forwardings(pf_objs)
        elif event_type == events.DELETED:
            self.mapping.del_port_forwardings(pf_objs)

    def _process_create(self,
                        port_forwardings: List[RGPortForwarding],
                        ri: RouterInfo,
                        interface_name: str,
                        interface_ip: str,
                        namespace: str,
                        iptables_manager: IptablesManager):
        if not port_forwardings:
            return

        ha_port = ri.router.get(constants.HA_INTERFACE_KEY, None)
        if ha_port and ha_port['status'] == constants.PORT_STATUS_ACTIVE:
            ri.enable_keepalived()

        for port_forwarding in port_forwardings:
            if port_forwarding.id in self.mapping.managed_port_forwardings:
                LOG.debug("Skip port forwarding %s for create, as it had been "
                          "managed by agent", port_forwarding.id)
                continue
            rule_tag = PORT_FORWARDING_PREFIX + port_forwarding.id
            port_forwarding.gw_ip_address = interface_ip
            self._rule_apply(iptables_manager, port_forwarding, rule_tag)
        iptables_manager.apply()
        self._store_local(port_forwardings, events.CREATED)

    def _process_update(self,
                        port_forwardings: List[RGPortForwarding],
                        interface_name: str,
                        interface_ip: str,
                        namespace: str,
                        iptables_manager: IptablesManager):
        if not port_forwardings:
            return
        device = IPDevice(interface_name, namespace=namespace)
        for port_forwarding in port_forwardings:
            # check if port forwarding change from OVO and router rpc
            if not self.mapping.check_port_forwarding_changes(port_forwarding):
                LOG.debug("Skip port forwarding %s for update, as there is no "
                          "difference between the memory managed by agent",
                          port_forwarding.id)
                continue
            current_chain = _get_port_forwarding_chain_name(port_forwarding.id)
            iptables_manager.ipv4['nat'].remove_chain(current_chain)
            ori_pf = self.mapping.managed_port_forwardings[port_forwarding.id]
            device.delete_socket_conntrack_state(interface_ip,
                                                 ori_pf.external_port,
                                                 protocol=ori_pf.protocol)
            rule_tag = PORT_FORWARDING_PREFIX + port_forwarding.id
            port_forwarding.gw_ip_address = interface_ip
            self._rule_apply(iptables_manager, port_forwarding, rule_tag)
        iptables_manager.apply()
        self._store_local(port_forwardings, events.UPDATED)

    @coordination.synchronized('router-lock-ns-{namespace}')
    def _process_delete(self,
                        port_forwardings: List[RGPortForwarding],
                        interface_name: str,
                        interface_ip: str,
                        namespace: str,
                        iptables_manager: IptablesManager):
        if not port_forwardings:
            return
        device = IPDevice(interface_name, namespace=namespace)
        for port_forwarding in port_forwardings:
            current_chain = _get_port_forwarding_chain_name(port_forwarding.id)
            iptables_manager.ipv4['nat'].remove_chain(current_chain)
            device.delete_socket_conntrack_state(
                interface_ip,
                port_forwarding.external_port,
                protocol=port_forwarding.protocol)

        iptables_manager.apply()

        self._store_local(port_forwardings, events.DELETED)

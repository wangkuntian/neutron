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


from oslo_log import log as logging
from typing import List, Dict, Optional

from neutron_lib import constants
from neutron_lib.context import Context
from neutron_lib.plugins import directory
from neutron_lib.db import resource_extend
from neutron_lib.plugins.constants import L3
from neutron_lib.db.api import CONTEXT_WRITER
from neutron_lib.exceptions import PortNotFound
from neutron_lib.exceptions.l3 import RouterNotFound
from neutron_lib.callbacks import registry, resources
from neutron_lib.callbacks import events as lib_events
from neutron_lib.callbacks.events import DBEventPayload
from neutron_lib.api.definitions import rg_port_forwarding as apidef
from neutron_lib.objects.exceptions import NeutronDbObjectDuplicateEntry

from neutron.db import db_base_plugin_common
from neutron.db.l3_dvr_db import is_distributed_router
from neutron.db.l3_hamode_db import is_ha_router

from neutron.objects.base import Pager
from neutron.objects.ports import Port
from neutron.objects.router import Router, FloatingIP
from neutron.objects.rg_port_forwarding import RGPortForwarding
from neutron.objects.rg_port_forwarding import FIELDS_NOT_SUPPORT_FILTER

from neutron.extensions.rg_port_forwarding import RGPortForwardingPluginBase
from neutron.services.l3_router.l3_router_plugin import L3RouterPlugin
from neutron.services.rg_portforwarding.common import exceptions

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.handlers import resources_rpc

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class RGPortForwardingPlugin(RGPortForwardingPluginBase):
    required_service_plugins = ['router']

    supported_extension_aliases = [apidef.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        super(RGPortForwardingPlugin, self).__init__()
        self.push_api = resources_rpc.ResourcesPushRpcApi()
        self.l3_plugin = directory.get_plugin(L3)
        self.core_plugin = directory.get_plugin()

    @staticmethod
    def _get_router(context: Context, router_id: str) -> Optional[Router]:
        router = Router.get_object(context, id=router_id)
        if not router:
            raise RouterNotFound(router_id=router_id)
        return router

    @staticmethod
    def _get_router_gateway(context: Context, router: Router) -> str:
        gw_port_id = router.get('gw_port_id', None)
        if not gw_port_id:
            raise exceptions.RouterDoesNotHaveGateway(router_id=router.id)
        gw_port = Port.get_object(
            context, id=gw_port_id)
        if not gw_port:
            raise exceptions.RouterGatewayPortNotFound(router_id=router.id,
                                                       gw_port_id=gw_port_id)
        gw_port_ips = gw_port.get("fixed_ips", [])
        if len(gw_port_ips) <= 0:
            raise exceptions.RouterGatewayPortDoesNotHaveAnyIPAddresses(
                router_id=router.id, gw_port_id=gw_port_id)
        gw_ip_address = gw_port_ips[0].get('ip_address')
        return gw_ip_address

    @staticmethod
    def _get_port(context: Context, port_id: str) -> Optional[Port]:
        port = Port.get_object(context, id=port_id)
        if not port:
            raise PortNotFound(port_id=port_id)
        return port

    @staticmethod
    def _get_ports(context: Context, router_id: str, port: Port,
                   device_owner: str) -> Optional[List[Port]]:
        ports = Port.get_ports_by_router_and_network(
            context, router_id, device_owner, port.network_id)
        if not ports:
            raise exceptions.PortNetworkNotBindOnRouter(
                port_id=port.id,
                network_id=port.network_id,
                router_id=router_id)
        return ports

    @staticmethod
    def _validate_filter_for_port_forwarding(filters: Dict[str, str]) -> None:
        if not filters:
            return
        for filter_member_key in filters.keys():
            if filter_member_key in FIELDS_NOT_SUPPORT_FILTER:
                raise exceptions.PortForwardingNotSupportFilterField(
                    filter=filter_member_key)

    @staticmethod
    def _check_port_has_binding_floating_ip(context: Context, port_id: str,
                                            ip_address: str) -> None:
        floatingip_objs = FloatingIP.get_objects(
            context.elevated(),
            fixed_port_id=port_id)
        if floatingip_objs:
            floating_ip_address = floatingip_objs[0].floating_ip_address
            raise exceptions.PortHasBindingFloatingIP(
                floating_ip_address=floating_ip_address,
                fip_id=floatingip_objs[0].id,
                port_id=port_id,
                fixed_ip=ip_address)

    @staticmethod
    def _get_device_owner(router: Router) -> str:
        if is_distributed_router(router):
            return constants.DEVICE_OWNER_DVR_INTERFACE
        elif is_ha_router(router):
            return constants.DEVICE_OWNER_HA_REPLICATED_INT
        return constants.DEVICE_OWNER_ROUTER_INTF

    def _check_router_port(self, context: Context, router: Router,
                           port: Port):
        device_owner = self._get_device_owner(router)
        self._get_ports(context, router.id, port, device_owner)

    def _check_port(self, context: Context, port_id: str, ip: str) -> Port:
        port = self._get_port(context, port_id)
        self._check_port_has_binding_floating_ip(context, port_id, ip)
        fixed_ips = port.get('fixed_ips', [])
        result = list(map(lambda x: str(x.get('ip_address')) == ip, fixed_ips))
        if not any(result):
            raise exceptions.InconsistentPortAndIP(port_id=port, ip_address=ip)
        return port

    def _check_router(self, context: Context, router_id: str) -> (Router, str):
        router = self._get_router(context, router_id)
        gw_ip_address = self._get_router_gateway(context, router)
        return router, gw_ip_address

    def _check_port_forwarding_create(self, context: Context, router_id: str,
                                      pf_dict: Dict) -> None:
        router, gw_ip_address = self._check_router(context, router_id)
        pf_dict['router_id'] = router_id
        pf_dict[apidef.GW_IP_ADDRESS] = gw_ip_address
        internal_port_id = pf_dict[apidef.INTERNAL_PORT_ID]
        internal_ip_address = pf_dict[apidef.INTERNAL_IP_ADDRESS]
        internal_port = self._check_port(context, internal_port_id,
                                         internal_ip_address)
        self._check_router_port(context, router, internal_port)

    @staticmethod
    def _check_port_forwarding(context: Context, pf_obj: RGPortForwarding):
        pf_objs = RGPortForwarding.get_objects(
            context,
            router_id=pf_obj.router_id,
            protocol=pf_obj.protocol)

        for obj in pf_objs:
            if obj.id == pf_obj.get('id', None):
                continue
            # Ensure there are no conflicts on the outside
            if obj.external_port == pf_obj.external_port:
                raise exceptions.RouterGatewayPortForwardingAlreadyExists(
                    conflict={
                        'router_id': pf_obj.router_id,
                        'protocol': pf_obj.protocol,
                        'external_port': obj.external_port,
                    }
                )
            # Ensure there are no conflicts in the inside
            # socket: internal_ip_address + internal_port
            if (obj.internal_port_id == pf_obj.internal_port_id and
                    obj.internal_ip_address == pf_obj.internal_ip_address and
                    obj.internal_port == pf_obj.internal_port):
                raise exceptions.RouterGatewayPortForwardingAlreadyExists(
                    conflict={
                        'router_id': pf_obj.router_id,
                        'protocol': pf_obj.protocol,
                        'internal_port_id': obj.internal_port_id,
                        'internal_ip_address': str(obj.internal_ip_address),
                        'internal_port': obj.internal_port
                    }
                )

    @staticmethod
    def _find_existing_rg_port_forwarding(context: Context,
                                          router_id: str,
                                          port_forwarding: Dict,
                                          specify_params: List = None):
        # Because the session had been flushed by NeutronDbObjectDuplicateEntry
        # so if we want to use the context to get another db queries, we need
        # to rollback first.
        context.session.rollback()
        if not specify_params:
            specify_params = [
                {
                    'router_id': router_id,
                    'external_port': port_forwarding['external_port'],
                    'protocol': port_forwarding['protocol']
                },
                {
                    'internal_port_id': port_forwarding['internal_port_id'],
                    'internal_ip_address': port_forwarding[
                        'internal_ip_address'],
                    'internal_port': port_forwarding['internal_port'],
                    'protocol': port_forwarding['protocol']
                }]
        for param in specify_params:
            objs = RGPortForwarding.get_objects(context, **param)
            if objs:
                return objs[0], param

    @db_base_plugin_common.make_result_with_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_router_gateway_port_forwardings(self, context: Context,
                                            router_id: str,
                                            filters: List[str] = None,
                                            fields: List[str] = None,
                                            sorts: List[str] = None,
                                            limit: int = None,
                                            marker: str = None,
                                            page_reverse: bool = False):

        router, gw_ip_address = self._check_router(context, router_id)
        filters = filters or {}
        self._validate_filter_for_port_forwarding(filters)
        pager = Pager(sorts, limit, page_reverse, marker)
        port_forwardings = RGPortForwarding.get_objects(
            context, _pager=pager, router_id=router_id, **filters)
        for pf in port_forwardings:
            setattr(pf, 'gw_ip_address', gw_ip_address)
        return port_forwardings

    @db_base_plugin_common.convert_result_to_dict
    def create_router_gateway_port_forwarding(self, context: Context,
                                              router_id: str,
                                              gateway_port_forwarding: dict):
        port_forwarding = gateway_port_forwarding.get(apidef.RESOURCE_NAME)
        self._check_port_forwarding_create(context, router_id, port_forwarding)
        with CONTEXT_WRITER.using(context):
            pf_obj = RGPortForwarding(context, **port_forwarding)
            self._check_port_forwarding(context, pf_obj)
            try:
                pf_obj.create()
            except NeutronDbObjectDuplicateEntry:
                _, conflict = self._find_existing_rg_port_forwarding(
                    context, router_id, port_forwarding)
                raise exceptions.RouterGatewayPortForwardingAlreadyExists(
                    conflict=conflict
                )
        self.push_api.push(context, [pf_obj], events.CREATED)
        return pf_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_router_gateway_port_forwarding(self, context: Context, id: str,
                                              router_id: str,
                                              gateway_port_forwarding: dict):

        router = self._get_router(context, router_id)
        gw_ip_address = self._get_router_gateway(context, router)
        pf_obj = RGPortForwarding.get_object(context, id=id)
        if not pf_obj:
            raise exceptions.RouterGatewayPortForwardingNotFound(id=id)

        port_forwarding = gateway_port_forwarding.get(apidef.RESOURCE_NAME, {})
        port_forwarding[apidef.GW_IP_ADDRESS] = gw_ip_address
        new_port_id = port_forwarding.get(apidef.INTERNAL_PORT_ID)
        new_internal_ip = port_forwarding.get(apidef.INTERNAL_IP_ADDRESS, None)

        if new_port_id and new_port_id != pf_obj.internal_port_id:
            self._check_port_has_binding_floating_ip(context,
                                                     new_port_id,
                                                     new_internal_ip)

        if any([new_internal_ip, new_port_id]):
            port_forwarding.update({
                apidef.INTERNAL_IP_ADDRESS: new_internal_ip
                if new_internal_ip else
                str(pf_obj.internal_ip_address),
                apidef.INTERNAL_PORT_ID: new_port_id
                if new_port_id else pf_obj.internal_port
            })

        with CONTEXT_WRITER.using(context):
            pf_obj.update_fields(port_forwarding, reset_changes=True)
            self._check_port_forwarding(context, pf_obj)
            try:
                pf_obj.update()
            except NeutronDbObjectDuplicateEntry:
                _, conflict = self._find_existing_rg_port_forwarding(
                    context, router_id, port_forwarding)
                raise exceptions.RouterGatewayPortForwardingAlreadyExists(
                    conflict=conflict
                )
        self.push_api.push(context, [pf_obj], events.UPDATED)
        return pf_obj

    @db_base_plugin_common.make_result_with_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_router_gateway_port_forwarding(self, context: Context, id: str,
                                           router_id: str,
                                           fields: List[str] = None):
        _, gw_ip_address = self._check_router(context, router_id)
        pf_obj = RGPortForwarding.get_object(context, id=id)
        if not pf_obj:
            raise exceptions.RouterGatewayPortForwardingNotFound(id=id)
        setattr(pf_obj, apidef.GW_IP_ADDRESS, gw_ip_address)
        return pf_obj

    def delete_router_gateway_port_forwarding(self, context: Context, id: str,
                                              router_id: str):
        pf_obj = RGPortForwarding.get_object(context, id=id)
        if not pf_obj:
            raise exceptions.RouterGatewayPortForwardingNotFound(id=id)
        with CONTEXT_WRITER.using(context):
            pf_obj.delete()
        self.push_api.push(context, [pf_obj], events.DELETED)

    @registry.receives(resources.ROUTER, [lib_events.BEFORE_DELETE])
    def _receive_router_before_delete(self, resource: str, event: str,
                                      trigger: L3RouterPlugin,
                                      payload: DBEventPayload):
        router_id = payload.resource_id
        context = payload.context
        port_forwardings = RGPortForwarding.get_objects(context,
                                                        router_id=router_id)
        if port_forwardings:
            ex = exceptions.DeletedRouterWithRGForwarding(router_id=router_id)
            LOG.info(ex.msg)
            raise ex

    @registry.receives(resources.ROUTER_GATEWAY, [lib_events.BEFORE_DELETE,
                                                  lib_events.BEFORE_UPDATE])
    def _receive_router_gateway_before_delete(self, resource: str, event: str,
                                              trigger: L3RouterPlugin,
                                              payload: DBEventPayload):
        router_id = payload.resource_id
        context = payload.context
        port_forwardings = RGPortForwarding.get_objects(context,
                                                        router_id=router_id)
        if port_forwardings:
            ex = exceptions.DeletedRouterGatewayWithRGForwarding(
                router_id=router_id)
            LOG.info(ex.msg)
            raise ex

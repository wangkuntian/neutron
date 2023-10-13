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

import six
import abc
import itertools
from typing import List

from neutron_lib.context import Context
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from neutron_lib.api.extensions import APIExtensionDescriptor
from neutron_lib.api.definitions import rg_port_forwarding as apidef

from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.api.extensions import ResourceExtension


class Rg_port_forwarding(APIExtensionDescriptor):
    api_definition = apidef

    @classmethod
    def get_plugin_interface(cls):
        return RGPortForwardingPluginBase

    @classmethod
    def get_resources(cls):
        special_mappings = {'routers': 'router'}
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings,
            itertools.chain(
                apidef.RESOURCE_ATTRIBUTE_MAP,
                apidef.SUB_RESOURCE_ATTRIBUTE_MAP
            )
        )

        resources = resource_helper.build_resource_info(
            plural_mappings,
            apidef.RESOURCE_ATTRIBUTE_MAP,
            constants.ROUTER_GATEWAY_PORTFORWARDING,
            translate_name=True,
            allow_bulk=True)

        plugin = directory.get_plugin(constants.ROUTER_GATEWAY_PORTFORWARDING)

        parent = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[apidef.COLLECTION_NAME].get(
            'parent')
        params = apidef.SUB_RESOURCE_ATTRIBUTE_MAP[apidef.COLLECTION_NAME].get(
            'parameters')
        controller = base.create_resource(
            apidef.COLLECTION_NAME, apidef.RESOURCE_NAME, plugin, params,
            allow_bulk=True, parent=parent, allow_pagination=True,
            allow_sorting=True)

        resource = ResourceExtension(
            apidef.COLLECTION_NAME, controller, parent, attr_map=params)
        resources.append(resource)

        return resources


@six.add_metaclass(abc.ABCMeta)
class RGPortForwardingPluginBase(service_base.ServicePluginBase):
    path_prefix = apidef.API_PREFIX

    @classmethod
    def get_plugin_type(cls):
        return constants.ROUTER_GATEWAY_PORTFORWARDING

    def get_plugin_description(self):
        return "Router Gateway Port Forwarding Service Plugin"

    @abc.abstractmethod
    def create_router_gateway_port_forwarding(self, context: Context,
                                              router_id: str,
                                              gateway_port_forwarding: dict):
        pass

    @abc.abstractmethod
    def update_router_gateway_port_forwarding(self, context: Context, id: str,
                                              router_id: str,
                                              gateway_port_forwarding: dict):
        pass

    @abc.abstractmethod
    def get_router_gateway_port_forwarding(self, context: Context, id: str,
                                           router_id: str,
                                           fields: List[str] = None):
        pass

    @abc.abstractmethod
    def get_router_gateway_port_forwardings(self, context: Context,
                                            router_id: str,
                                            filters: List[str] = None,
                                            fields: List[str] = None,
                                            sorts: List[str] = None,
                                            limit: int = None,
                                            marker: str = None,
                                            page_reverse: bool = False):
        pass

    @abc.abstractmethod
    def delete_router_gateway_port_forwarding(self, context: Context, id: str,
                                              router_id: str):
        pass

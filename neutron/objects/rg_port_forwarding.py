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

import netaddr
from neutron_lib import constants as lib_const
from oslo_versionedobjects import fields as obj_fields

from neutron.objects import base, common_types
from neutron.db.models import rg_port_forwarding as models

FIELDS_NOT_SUPPORT_FILTER = ['internal_ip_address', 'internal_port']


@base.NeutronObjectRegistry.register
class RGPortForwarding(base.NeutronDbObject):
    VERSION = '1.0'

    db_model = models.RGPortForwarding

    primary_keys = ['id']
    foreign_keys = {
        'Router': {'router_id': 'id'},
        'Port': {'internal_port_id': 'id'}
    }
    fields_need_translation = {
        'socket': 'socket',
        'internal_port_id': 'internal_neutron_port_id'
    }

    fields = {
        'id': common_types.UUIDField(),
        'router_id': common_types.UUIDField(nullable=False),
        'external_port': common_types.PortRangeField(nullable=False),
        'protocol': common_types.IpProtocolEnumField(nullable=False),
        'internal_port_id': common_types.UUIDField(nullable=False),
        'internal_ip_address': obj_fields.IPV4AddressField(),
        'internal_port': common_types.PortRangeField(nullable=False),
        'gw_ip_address': obj_fields.IPV4AddressField(),
    }

    synthetic_fields = ['gw_ip_address']
    fields_no_update = {'id', 'router_id'}

    def __eq__(self, other):
        for attr in self.fields:
            if getattr(self, attr) != getattr(other, attr):
                return False
        return True

    def obj_load_attr(self, attrname):
        super(RGPortForwarding, self).obj_load_attr(attrname)

    def from_db_object(self, db_obj):
        super(RGPortForwarding, self).from_db_object(db_obj)

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super(RGPortForwarding, cls).modify_fields_from_db(db_obj)
        if 'socket' in result:
            groups = result['socket'].split(":")
            result['internal_ip_address'] = netaddr.IPAddress(
                groups[0], version=lib_const.IP_VERSION_4)
            result['internal_port'] = int(groups[1])
            del result['socket']
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(RGPortForwarding, cls).modify_fields_to_db(fields)
        if 'internal_ip_address' in result and 'internal_port' in result:
            result['socket'] = (f"{result['internal_ip_address']}:"
                                f"{result['internal_port']}")
            del result['internal_ip_address']
            del result['internal_port']
        return result

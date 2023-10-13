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


from oslo_policy import policy
from neutron.conf.policies import base

COLLECTION_PATH = '/routers/{router_id}/port_forwardings'
RESOURCE_PATH = '/routers/{router_id}/port_forwardings/{port_forwarding_id}'

rules = [
    policy.DocumentedRuleDefault(
        'create_router_gateway_port_forwarding',
        base.RULE_ADMIN_OR_PARENT_OWNER,
        'Create a router gateway port forwarding',
        [
            {
                'method': 'POST',
                'path': COLLECTION_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_router_gateway_forwarding',
        base.RULE_ADMIN_OR_PARENT_OWNER,
        'Get a router gateway port forwarding',
        [
            {
                'method': 'GET',
                'path': COLLECTION_PATH,
            },
            {
                'method': 'GET',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_router_gateway_port_forwarding',
        base.RULE_ADMIN_OR_PARENT_OWNER,
        'Update a floating IP port forwarding',
        [
            {
                'method': 'PUT',
                'path': RESOURCE_PATH,
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_router_gateway_port_forwarding',
        base.RULE_ADMIN_OR_PARENT_OWNER,
        'Delete a floating IP port forwarding',
        [
            {
                'method': 'DELETE',
                'path': RESOURCE_PATH,
            },
        ]
    ),
]


def list_rules():
    return rules

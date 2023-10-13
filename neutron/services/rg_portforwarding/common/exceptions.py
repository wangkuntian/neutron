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

from neutron._i18n import _
from neutron_lib import exceptions


class PortForwardingNotSupportFilterField(exceptions.BadRequest):
    message = _("Port Forwarding filter %(filter)s is not supported.")


class RouterDoesNotHaveGateway(exceptions.BadRequest):
    message = _("Router %(router_id)s does not have any gateways.")


class RouterGatewayPortNotFound(exceptions.NotFound):
    message = _("Router %(router_id)s 's gateway port %(gw_port_id)s "
                "could not be found.")


class RouterGatewayPortDoesNotHaveAnyIPAddresses(exceptions.NotFound):
    message = _("Router %(router_id)s 's gateway port %(gw_port_id)s "
                "does not have any IP addresses.")


class RouterGatewayPortForwardingNotFound(exceptions.NotFound):
    message = _("Router Gateway Port Forwarding %(id)s could not be found.")


class PortHasBindingFloatingIP(exceptions.InUse):
    message = _("Cannot create port forwarding to floating IP "
                "%(floating_ip_address)s (%(fip_id)s) with port %(port_id)s "
                "using fixed IP %(fixed_ip)s, as that port already "
                "has a binding floating IP.")


class InconsistentPortAndIP(exceptions.BadRequest):
    message = _("Port %(port_id)s does not have ip address %(ip_address)s.")


class RouterGatewayPortForwardingAlreadyExists(exceptions.BadRequest):
    message = _("A duplicate router gateway port forwarding entry "
                "with same attributes already exists, "
                "conflicting values are %(conflict)s.")


class PortNetworkNotBindOnRouter(exceptions.BadRequest):
    message = _("Port %(port_id)s 's network %(network_id)s "
                "not bind on router %(router_id)s.")


class RouterGatewayPortForwardingUpdateFailed(exceptions.BadRequest):
    message = _("Another router port forwarding entry with the same "
                "attributes already exists, conflicting "
                "values are %(conflict)s.")


class DeletedRouterWithRGForwarding(exceptions.InUse):
    message = _("Cant not delete router, "
                "router %(router_id)s has port forwardings to remove.")


class DeletedRouterGatewayWithRGForwarding(exceptions.InUse):
    message = _("Cant not delete or update router gateway, "
                "router %(router_id)s has port forwardings to remove.")

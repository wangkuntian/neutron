# Copyright 2022 Red Hat, Inc.
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

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.tests.functional import base


class TestCreateNeutronPgDrop(base.TestOVNFunctionalBase):
    def test_already_existing(self):
        # Make sure pre-fork initialize created the table
        existing_pg = self.nb_api.pg_get(
            ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        self.assertIsNotNone(existing_pg)

        # make an attempt to create it again
        utils.create_neutron_pg_drop()

        pg = self.nb_api.pg_get(ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        self.assertEqual(existing_pg.uuid, pg.uuid)

    def test_non_existing(self):
        # Delete the neutron_pg_drop created by pre-fork initialize
        self.nb_api.pg_del(ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        pg = self.nb_api.pg_get(ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        self.assertIsNone(pg)

        utils.create_neutron_pg_drop()

        pg = self.nb_api.pg_get(ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        self.assertIsNotNone(pg)

        directions = ['to-lport', 'from-lport']
        matches = ['outport == @neutron_pg_drop && ip',
                   'inport == @neutron_pg_drop && ip']

        # Make sure ACLs are correct
        self.assertEqual(2, len(pg.acls))
        acl1, acl2 = pg.acls

        self.assertEqual('drop', acl1.action)
        self.assertIn(acl1.direction, directions)
        directions.remove(acl1.direction)
        self.assertIn(acl1.match, matches)
        matches.remove(acl1.match)

        self.assertEqual(directions[0], acl2.direction)
        self.assertEqual('drop', acl2.action)
        self.assertEqual(matches[0], acl2.match)


class TestSyncHaChassisGroup(base.TestOVNFunctionalBase):

    def test_sync_ha_chassis_group(self):
        net = self._make_network(self.fmt, 'n1', True)['network']
        hcg_name = utils.ovn_name(net['id'])
        chassis1 = self.add_fake_chassis('host1', azs=[],
                                         enable_chassis_as_gw=True)
        chassis2 = self.add_fake_chassis('host2', azs=[],
                                         enable_chassis_as_gw=True)
        self.add_fake_chassis('host3')

        with self.nb_api.transaction(check_error=True) as txn:
            utils.sync_ha_chassis_group(self.context, net['id'], self.nb_api,
                                        self.sb_api, txn)

        ha_chassis = self.nb_api.db_find('HA_Chassis').execute(
            check_error=True)
        ha_chassis_names = [hc['chassis_name'] for hc in ha_chassis]
        self.assertEqual(2, len(ha_chassis))
        self.assertEqual(sorted([chassis1, chassis2]),
                         sorted(ha_chassis_names))

        hcg = self.nb_api.ha_chassis_group_get(hcg_name).execute(
            check_error=True)
        self.assertEqual(hcg_name, hcg.name)
        ha_chassis_exp = sorted([str(hc['_uuid']) for hc in ha_chassis])
        ha_chassis_ret = sorted([str(hc.uuid) for hc in hcg.ha_chassis])
        self.assertEqual(ha_chassis_exp, ha_chassis_ret)

        # Delete one GW chassis and resync the HA chassis group associated to
        # the same network. The method will now not create again the existing
        # HA Chassis Group register but will update the "ha_chassis" list.
        self.del_fake_chassis(chassis2)
        with self.nb_api.transaction(check_error=True) as txn:
            utils.sync_ha_chassis_group(self.context, net['id'], self.nb_api,
                                        self.sb_api, txn)

        ha_chassis = self.nb_api.db_find('HA_Chassis').execute(
            check_error=True)
        ha_chassis_names = [hc['chassis_name'] for hc in ha_chassis]
        self.assertEqual(1, len(ha_chassis))
        self.assertEqual([chassis1], ha_chassis_names)

        hcg = self.nb_api.ha_chassis_group_get(hcg_name).execute(
            check_error=True)
        self.assertEqual(hcg_name, hcg.name)
        ha_chassis_exp = str(ha_chassis[0]['_uuid'])
        ha_chassis_ret = str(hcg.ha_chassis[0].uuid)
        self.assertEqual(ha_chassis_exp, ha_chassis_ret)

# Copyright 2023 OpenStack Foundation
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
#

from alembic import op
import sqlalchemy as sa

"""add router configurations

Revision ID: 1c19a98b5eef
Revises: cab12b72ed90
Create Date: 2023-08-01 10:05:56.412167

"""

# revision identifiers, used by Alembic.
revision = '1c19a98b5eef'
down_revision = 'cab12b72ed90'


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('router_extra_attributes',
                  sa.Column('configurations', sa.String(length=4095)))
    # ### end Alembic commands ###
#Copyright (c) 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from sqlalchemy.orm import sessionmaker

from models import melange
from quark.db import models as quarkmodels


quarkmodels.BASEV2.metadata.create_all(melange.engine)


def loadSession():
    #metadata = Base.metadata
    Session = sessionmaker(bind=melange.engine)
    session = Session()
    return session


def migrate():
    """
    This will migrate an existing melange database to a new quark
    database. Below melange is referred to as m and quark as q.
    """
    """1. Migrate the m.interfaces -> q.quark_networks

    This is a trivial migration. Copy the created_at, tenant_id, name,
    and id over.
    May need to store the m.vif_id_on_device for q.port later and the
    m.device_id for q.port

    quark columns maybe:
    quark_ports.backend_key, device_id

    """

    """2. Migrate the m.mac_address -> q.quark_mac_addresses
    This is the next simplest but the relationship between quark_networks
    and quark_mac_addresses may be complicated to set up (if it exists)
    """

    """3. Migrate m.ip_addresses -> q.quark_ip_addresses
    This migration is complicated. I believe q.subnets will need to be
    populated during this step as well. m.ip_addresses is scattered all
    over the place and it is not a 1:1 relationship between m -> q.
    Some more thought will be needed for this one.
    """
    pass


if __name__ == "__main__":
    session = loadSession()
    res = session.query(melange.Interfaces).all()
    print res[1].device_id

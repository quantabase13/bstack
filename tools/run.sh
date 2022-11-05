#!/bin/bash -e

sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip bin/test
sudo ip netns exec TEST su $USER -c "bin/test $1"
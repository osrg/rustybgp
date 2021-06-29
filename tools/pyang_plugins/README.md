# What's this ?

This is a pyang plugin to generate config/gen.rs from
[OpenConfig YANG files](https://github.com/openconfig/public).

## How to use

You must use Python 2.7 versions. Set the environment variables for this tool:

```bash
$ SOURCE=$HOME/git
$ RUSTYBGP=$SOURCE/rustybgp
```

Clone the required resources by using git:

```bash
$ cd $SOURCE
$ git clone https://github.com/osrg/public
$ git clone https://github.com/osrg/yang
$ git clone https://github.com/osrg/pyang
```

Setup environments for pyang:

```bash
$ cd $SOURCE/pyang
$ source ./env.sh
```

Generate config/gen.rs from yang files:

```bash
$ PYTHONPATH=. ./bin/pyang \
--plugindir $RUSTYBGP/tools/pyang_plugins \
-p $SOURCE/yang/standard/ietf/RFC \
-p $SOURCE/public/release/models \
-p $SOURCE/public/release/models/bgp \
-p $SOURCE/public/release/models/policy \
-f rust \
$SOURCE/public/release/models/bgp/openconfig-bgp.yang \
$SOURCE/public/release/models/policy/openconfig-routing-policy.yang \
$RUSTYBGP/tools/pyang_plugins/gobgp.yang > \
$RUSTYBGP/daemon/src/config/gen.rs
```

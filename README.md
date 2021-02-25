# Simulation-as-a-Service (SaaS) Middleware

The SaaS Middleware provides the necessary infrastructure to faciliate deployment and operations of a loosely-coupled federation of models.

## Install Dependencies
```
pip3 install flask flask_cors requests jsonschema canonicaljson cryptography docker
```


## Install Package
For now, we are only creating local builds that are *not* uploaded to PyPi. The package can be installed from its local source as follows:
```
pip3 install /path/to/saas-middleware
```

Alternatively, the package can be manually built and installed as follows.

Install `build`:
```
pip3 install --upgrade build
```

From the root directory of the repository, initiate the build:
```
python3 -m build
```

Install the package:
```
pip3 install /path/to/saas-middleware/dist/saas-middleware-0.0.1.tar.gz
```

# Approov QuickStart - Python Django Token Check

[Approov](https://approov.io) is an API security solution used to verify that requests received by your backend services originate from trusted versions of your mobile apps.

This repo implements the Approov server-side request verification code in Python, which performs the verification check before allowing valid traffic to be processed by the API endpoint.

This is an Approov integration quickstart example for the Python Django framework. If you are looking for another Python integration you can check our list of [quickstarts](https://approov.io/docs/latest/approov-integration-examples/backend-api/), and if you don't find what you are looking for, then please let us know [here](https://approov.io/contact). Meanwhile, you can always use the framework agnostic [quickstart example](https://github.com/approov/quickstart-python-token-check) for Python, and you may find that's easily adaptable to your framework of choice.


## Approov Integration Quickstart

The quickstart was tested with the following Operating Systems:

* Ubuntu 20.04
* MacOS Big Sur
* Windows 10 WSL2 - Ubuntu 20.04

First, setup the [Appoov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli).

Now, register the API domain for which Approov will issues tokens:

```bash
approov api -add api.example.com
```

Next, enable your Approov `admin` role with:

```bash
eval `approov role admin`
```

Now, get your Approov Secret with the [Appoov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli):

```bash
approov secret -get base64
```

Next, add the [Approov secret](https://approov.io/docs/latest/approov-usage-documentation/#account-secret-key-export) to your project `.env` file:

```env
APPROOV_BASE64_SECRET=approov_base64_secret_here
```

Now, add to your `requirements.txt` file the [JWT dependency](https://github.com/jpadilla/pyjwt/):

```bash
PyJWT==1.7.1 # update the version to the latest one
```

Next, you need to install the dependency:

```bash
pip3 install -r requirements.txt
```

Now, add the [approov_middleware.py](/src/approov-protected-server/token-check/hello/approov_middleware.py) class to your project:

```python
from django.http import JsonResponse
from os import getenv
from dotenv import load_dotenv, find_dotenv
import base64
import jwt # https://github.com/jpadilla/pyjwt/

# @link https://django.readthedocs.io/en/stable/topics/http/middleware.html
class ApproovMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

        load_dotenv(find_dotenv(), override=True)

        # Token secret value obtained with the Approov CLI tool:
        #  - approov secret -get
        approov_base64_secret = getenv('APPROOV_BASE64_SECRET')

        if approov_base64_secret == None:
            raise ValueError("Missing the value for environment variable: APPROOV_BASE64_SECRET")

        self.APPROOV_SECRET = base64.b64decode(approov_base64_secret)

    def __call__(self, request):
        approov_token_claims = self.verifyApproovToken(request)

        if approov_token_claims == None:
            return JsonResponse({}, status = 401)

        return self.get_response(request)

    # @link https://approov.io/docs/latest/approov-usage-documentation/#backend-integration
    def verifyApproovToken(self, request):
        approov_token = request.headers.get("Approov-Token")

        # If we didn't find a token, then reject the request.
        if approov_token == None:
            # You may want to add some logging here.
            return None

        try:
            # Decode the Approov token explicitly with the HS256 algorithm to avoid
            # the algorithm None attack.
            approov_token_claims = jwt.decode(approov_token, self.APPROOV_SECRET, algorithms=['HS256'])
            return approov_token_claims
        except jwt.ExpiredSignatureError as e:
            # You may want to add some logging here.
            return None
        except jwt.InvalidTokenError as e:
            # You may want to add some logging here.
            return None

```

Finally, to activate the [Approov Middleware](/src/approov-protected-server/token-check/hello/approov_middleware.py) you just need to include it in the middleware list of your [Django settings](/src/approov-protected-server/token-check/hello/settings.py) as the first one in the list:

```python
MIDDLEWARE = [
    'YOUR_APP_NAME.approov_middleware.ApproovMiddleware',
    'django.middleware.security.SecurityMiddleware',
    # lines omitted
]
```

> **NOTE:** The Approov middleware is included as the first one in the list because you don't want to waste your server resources in processing requests that don't have a valid Approov token. This approach will help your server to handle more load under a Denial of Service(DoS) attack.

Not enough details in the bare bones quickstart? No worries, check the [detailed quickstarts](QUICKSTARTS.md) that contain a more comprehensive set of instructions, including how to test the Approov integration.


## More Information

* [Approov Overview](OVERVIEW.md)
* [Detailed Quickstarts](QUICKSTARTS.md)
* [Examples](EXAMPLES.md)
* [Testing](TESTING.md)

### System Clock

In order to correctly check for the expiration times of the Approov tokens is very important that the backend server is synchronizing automatically the system clock over the network with an authoritative time source. In Linux this is usually done with a NTP server.


## Issues

If you find any issue while following our instructions then just report it [here](https://github.com/approov/quickstart-python-django-token-check/issues), with the steps to reproduce it, and we will sort it out and/or guide you to the correct path.


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

* [Approov Free Trial](https://approov.io/signup)(no credit card needed)
* [Approov Get Started](https://approov.io/product/demo)
* [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
* [Approov Docs](https://approov.io/docs)
* [Approov Blog](https://approov.io/blog/)
* [Approov Resources](https://approov.io/resource/)
* [Approov Customer Stories](https://approov.io/customer)
* [Approov Support](https://approov.zendesk.com/hc/en-gb/requests/new)
* [About Us](https://approov.io/company)
* [Contact Us](https://approov.io/contact)
